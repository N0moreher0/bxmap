//! Bounded batch runner for independent dump files.

use crate::args::Args;
use crate::helpers::Format;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

pub fn run(mut args: Args) -> Result<(), String> {
    let mut paths = Vec::with_capacity(args.additional_paths.len() + 1);
    paths.push(args.path.clone());
    paths.append(&mut args.additional_paths);

    let output_dir = args
        .output_dir
        .as_deref()
        .ok_or_else(|| "batch scanning requires --output-dir <DIR>".to_string())?;
    if args.output.is_some() {
        return Err(
            "batch scanning uses --output-dir; do not combine it with -o/--output or config output"
                .to_string(),
        );
    }
    if paths.len() < 2 && args.parallel_files_explicit {
        return Err("--parallel-files requires at least two input paths".to_string());
    }
    if args.parallel_files > 1 && paths.len() < 2 {
        return Err(
            "--parallel-files is greater than 1 but only one input path was supplied".to_string(),
        );
    }
    if args.progress == Some(true) && paths.len() > 1 {
        return Err("--progress cannot be combined with batch mode; per-file progress is disabled to keep worker status readable".to_string());
    }
    reject_unisolated_features(&args, &paths)?;
    std::fs::create_dir_all(output_dir)
        .map_err(|error| format!("cannot create output directory '{}': {error}", output_dir))?;

    // Preflight every destination and staging path before starting workers.
    // Sink::open uses File::create, so a rerun must never truncate prior data.
    let mut destinations = Vec::with_capacity(paths.len());
    let mut staged_outputs = Vec::with_capacity(paths.len());
    for (index, input) in paths.iter().enumerate() {
        let destination = output_path(output_dir, index, input, args.format);
        ensure_path_absent(&destination)?;
        let staged = staged_output_path(&destination);
        ensure_path_absent(&staged)?;
        destinations.push(destination);
        staged_outputs.push(staged);
    }

    if paths.len() == 1 {
        args.output = Some(staged_outputs[0].to_string_lossy().into_owned());
        args.output_dir = None;
        let result = crate::run_single_scan(args);
        return publish_output(result, &staged_outputs[0], &destinations[0]);
    }

    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1);
    let plan = plan_workers(
        paths.len(),
        args.parallel_files,
        cpus,
        args.auto_tune,
        args.threads,
        args.max_memory,
    )?;
    let jobs = plan.jobs;
    let threads_per_file = plan.threads_per_file;
    let per_job_memory = plan.per_job_memory;

    eprintln!(
        "[batch] {} inputs; {jobs} concurrent file jobs; up to {threads_per_file} scan threads per file; {} scanner-buffer budget",
        paths.len(),
        if args.max_memory == 0 {
            "unlimited".to_string()
        } else {
            format!("{} bytes total", args.max_memory)
        }
    );

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Result<(), String>>>> =
        Mutex::new((0..paths.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        let destinations = &destinations;
        let staged_outputs = &staged_outputs;
        for _ in 0..jobs {
            let paths = &paths;
            let results = &results;
            let next = &next;
            let base_args = args.clone();
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= paths.len() {
                    break;
                }
                let input = &paths[index];
                let output = &destinations[index];
                let staged_output = &staged_outputs[index];
                eprintln!(
                    "[batch {}/{}] scanning '{}' -> '{}'",
                    index + 1,
                    paths.len(),
                    input,
                    output.display()
                );
                let mut job_args = base_args.clone();
                job_args.path = input.clone();
                job_args.additional_paths.clear();
                job_args.parallel_files = 1;
                job_args.parallel_files_explicit = false;
                job_args.output_dir = None;
                job_args.output = Some(staged_output.to_string_lossy().into_owned());
                job_args.progress = Some(false);
                job_args.threads = threads_per_file;
                job_args.auto_tune = false;
                job_args.max_memory = per_job_memory;

                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::run_single_scan(job_args)
                }))
                .unwrap_or_else(|_| Err("scan worker panicked".to_string()));
                let result = publish_output(result, staged_output, output);
                results.lock().expect("batch result lock poisoned")[index] = Some(result);
            });
        }
    });

    let results = results
        .into_inner()
        .map_err(|_| "batch result lock poisoned".to_string())?;
    let mut completed = 0usize;
    let mut failures = Vec::new();
    for (index, result) in results.into_iter().enumerate() {
        match result.unwrap_or_else(|| Err("worker did not return a result".to_string())) {
            Ok(()) => completed += 1,
            Err(error) => failures.push(format!("{}: {error}", paths[index])),
        }
    }
    eprintln!("[batch] completed {completed}/{} input(s)", paths.len());
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "batch scan failed for {} input(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkerPlan {
    jobs: usize,
    threads_per_file: usize,
    per_job_memory: u64,
}

fn plan_workers(
    input_count: usize,
    requested_jobs: usize,
    cpus: usize,
    auto_tune: bool,
    requested_threads: usize,
    max_memory: u64,
) -> Result<WorkerPlan, String> {
    let jobs = requested_jobs.min(input_count).min(cpus.max(1));
    if jobs == 0 {
        return Err("batch worker count must be at least 1".to_string());
    }
    let cpu_share = (cpus.max(1) / jobs).max(1);
    let requested_per_file = if auto_tune {
        (cpu_share * 3 / 4).max(1)
    } else {
        requested_threads
    };
    let threads_per_file = requested_per_file.min(cpu_share).max(1);
    let per_job_memory = if max_memory == 0 {
        0
    } else {
        max_memory / jobs as u64
    };
    if max_memory > 0 && per_job_memory == 0 {
        return Err("--max-memory is too small for the requested batch concurrency".to_string());
    }
    let minimum = bxmap::scan_working_set_bytes(1);
    if per_job_memory > 0 && per_job_memory < minimum {
        return Err(format!(
            "--max-memory gives each active input {per_job_memory} bytes; at least {minimum} bytes are needed for one scanner worker"
        ));
    }
    Ok(WorkerPlan {
        jobs,
        threads_per_file,
        per_job_memory,
    })
}

fn ensure_path_absent(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "batch output '{}' already exists; choose an empty output directory to avoid overwriting data",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect batch output '{}': {error}",
            path.display()
        )),
    }
}

fn staged_output_path(destination: &Path) -> PathBuf {
    let file_name = destination
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("dump-output"));
    destination.with_file_name(format!("{}.partial", file_name.to_string_lossy()))
}

fn publish_output(
    scan_result: Result<(), String>,
    staged: &Path,
    destination: &Path,
) -> Result<(), String> {
    match scan_result {
        Ok(()) => std::fs::rename(staged, destination).map_err(|error| {
            let cleanup = std::fs::remove_file(staged);
            let cleanup_note = cleanup
                .err()
                .filter(|cleanup_error| cleanup_error.kind() != std::io::ErrorKind::NotFound)
                .map(|cleanup_error| format!("; could not remove partial output: {cleanup_error}"))
                .unwrap_or_default();
            format!(
                "cannot publish batch output '{}' from '{}': {error}{cleanup_note}",
                destination.display(),
                staged.display()
            )
        }),
        Err(error) => {
            let cleanup_note = std::fs::remove_file(staged)
                .err()
                .filter(|cleanup_error| cleanup_error.kind() != std::io::ErrorKind::NotFound)
                .map(|cleanup_error| format!("; could not remove partial output: {cleanup_error}"))
                .unwrap_or_default();
            if cleanup_note.is_empty() {
                Err(error)
            } else {
                Err(format!("{error}{cleanup_note}"))
            }
        }
    }
}

fn output_path(output_dir: &str, index: usize, input: &str, format: Format) -> PathBuf {
    let path = Path::new(input);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("dump");
    let safe_stem: String = stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let extension = match format {
        Format::Text => "txt",
        Format::Json | Format::JsonTree => "json",
        Format::Ndjson => "ndjson",
        Format::Csv => "csv",
        Format::Html => "html",
        Format::Markdown => "md",
    };
    Path::new(output_dir).join(format!("{:04}_{safe_stem}.{extension}", index + 1))
}

fn reject_unisolated_features(args: &Args, paths: &[String]) -> Result<(), String> {
    if paths.len() > 1 && args.report_mode != crate::ReportMode::None {
        return Err(
            "--report is not supported with multiple inputs yet; per-file report output is not isolated".to_string(),
        );
    }
    if args.tree || args.vmware_info {
        return Err("batch mode supports per-input string output; minidump tree and VMware info output are not isolated yet".to_string());
    }
    if args.carve.is_some()
        || args.carve_out.is_some()
        || args.carve_index.is_some()
        || args.reassemble
    {
        return Err(
            "batch mode does not support carving/reassembly yet; outputs need per-input isolation"
                .to_string(),
        );
    }
    for path in paths {
        let extension = Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(extension.as_str(), "vmss" | "vmsn") {
            return Err(format!(
                "batch mode does not support VMware state input '{}'; scan it separately",
                path
            ));
        }
        let mut magic = [0u8; 4];
        let is_minidump = std::fs::File::open(path)
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut magic))
            .is_ok()
            && magic == *b"MDMP";
        if is_minidump && !args.no_tree {
            return Err(format!(
                "batch minidump input '{}' requires --no-tree so string results go to its output file",
                path
            ));
        }
        if (args.in_module.is_some() || args.rwx_only || args.heap_only) && !is_minidump {
            return Err(format!(
                "input '{}' must be a valid minidump when using --in-module, --rwx-only or --heap-only",
                path
            ));
        }
        if is_minidump && (args.in_module.is_some() || args.rwx_only || args.heap_only) {
            bxmap::minidump::Minidump::open(path)
                .map_err(|error| format!("cannot parse minidump '{}': {error}", path))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_scan_removes_staged_output() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("result.txt.partial");
        let destination = dir.path().join("result.txt");
        std::fs::write(&staged, b"incomplete output").unwrap();

        let result = publish_output(
            Err("synthetic scan failure".to_string()),
            &staged,
            &destination,
        );

        assert_eq!(result.unwrap_err(), "synthetic scan failure");
        assert!(!staged.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn worker_plan_caps_concurrency_and_threads_to_cpu_capacity() {
        let plan = plan_workers(8, 6, 4, false, 8, 0).unwrap();

        assert_eq!(plan.jobs, 4);
        assert_eq!(plan.threads_per_file, 1);
        assert_eq!(plan.per_job_memory, 0);
    }

    #[test]
    fn worker_plan_divides_memory_by_active_jobs() {
        let per_worker = bxmap::scan_working_set_bytes(1);
        let total_budget = per_worker * 2 + 17;
        let plan = plan_workers(5, 2, 8, false, 3, total_budget).unwrap();

        assert_eq!(plan.jobs, 2);
        assert_eq!(plan.threads_per_file, 3);
        assert_eq!(plan.per_job_memory, total_budget / 2);
        assert!(plan.per_job_memory * plan.jobs as u64 <= total_budget);
    }

    #[test]
    fn worker_plan_rejects_memory_below_one_scanner_worker() {
        let minimum = bxmap::scan_working_set_bytes(1);

        let error = plan_workers(2, 2, 8, false, 1, minimum * 2 - 1).unwrap_err();

        assert!(error.contains("at least"));
    }
}

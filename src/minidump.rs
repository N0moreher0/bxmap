//! Minimal streaming parser for Windows minidump (`MDMP`) files.
//!
//! Only the directory and small metadata streams are read; the (potentially
//! multi-GB) memory payload is never loaded. The result is a process tree
//! (modules, threads, memory regions) plus helpers that map a file offset
//! (as reported by the string scanner) back to a virtual address and module.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

const MDMP_SIG: u32 = 0x504d_444d; // "MDMP" little-endian
const MAX_READ: u64 = 256 << 20; // refuse absurd metadata sizes

const ST_THREAD_LIST: u32 = 3;
const ST_MODULE_LIST: u32 = 4;
const ST_SYSTEM_INFO: u32 = 7;
const ST_MEMORY64_LIST: u32 = 9;
const ST_MISC_INFO: u32 = 15;
const ST_MEMORY_INFO_LIST: u32 = 16;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}
fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

struct Src<R> {
    r: R,
    len: u64,
}
impl<R: Read + Seek> Src<R> {
    fn new(mut r: R) -> io::Result<Self> {
        let len = r.seek(SeekFrom::End(0))?;
        Ok(Self { r, len })
    }
    fn bytes(&mut self, off: u64, n: u64) -> io::Result<Vec<u8>> {
        match off.checked_add(n) {
            Some(end) if end <= self.len => {}
            _ => return Err(bad("read past end of file")),
        }
        if n > MAX_READ {
            return Err(bad("metadata block too large"));
        }
        self.r.seek(SeekFrom::Start(off))?;
        let mut b = vec![0u8; n as usize];
        self.r.read_exact(&mut b)?;
        Ok(b)
    }
    fn utf16_string(&mut self, rva: u64) -> io::Result<String> {
        let l = u32le(&self.bytes(rva, 4)?, 0) as u64;
        let raw = self.bytes(rva + 4, l)?;
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub stream_count: u32,
    pub timestamp: u32,
    pub flags: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamEntry {
    pub stream_type: u32,
    pub size: u32,
    pub rva: u32,
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub arch: u16,
    pub cpu_count: u8,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}
impl SystemInfo {
    pub fn arch_name(&self) -> &'static str {
        match self.arch {
            0 => "x86",
            5 => "arm",
            9 => "x64",
            12 => "arm64",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Module {
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub id: u32,
    pub teb: u64,
    pub stack_start: u64,
    pub stack_size: u32,
}

/// One captured range of the Memory64List; `file_offset` is where its bytes
/// start inside the dump file.
#[derive(Debug, Clone)]
pub struct MemoryRange {
    pub start: u64,
    pub size: u64,
    pub file_offset: u64,
}

/// One virtual-memory region from MemoryInfoList (VirtualQuery data).
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub allocation_base: u64,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}
impl MemoryRegion {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_FREE: u32 = 0x10000;
    pub fn is_executable(&self) -> bool {
        self.protect & 0xF0 != 0
    }
    pub fn is_writable(&self) -> bool {
        self.protect & 0xCC != 0 // RW, WC, RWX, XWC
    }
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            0x20000 => "private",
            0x40000 => "mapped",
            0x1000000 => "image",
            _ => "-",
        }
    }
}

pub fn protect_name(p: u32) -> String {
    let base = match p & 0xFF {
        0x01 => "---",
        0x02 => "r--",
        0x04 => "rw-",
        0x08 => "rwc",
        0x10 => "--x",
        0x20 => "r-x",
        0x40 => "rwx",
        0x80 => "rwxc",
        0 => "-",
        _ => "?",
    };
    if p & 0x100 != 0 {
        format!("{base}+guard")
    } else {
        base.to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Minidump {
    pub header: Option<Header>,
    pub streams: Vec<StreamEntry>,
    pub system: Option<SystemInfo>,
    pub pid: Option<u32>,
    pub modules: Vec<Module>,
    pub threads: Vec<Thread>,
    pub ranges: Vec<MemoryRange>,
    pub regions: Vec<MemoryRegion>,
}

impl Minidump {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    pub fn from_reader<R: Read + Seek>(r: R) -> io::Result<Self> {
        let mut s = Src::new(r)?;
        let h = s.bytes(0, 32)?;
        if u32le(&h, 0) != MDMP_SIG {
            return Err(bad("not a minidump (missing MDMP signature)"));
        }
        let n = u32le(&h, 8) as u64;
        let dir_rva = u32le(&h, 12) as u64;
        let header = Header {
            version: u32le(&h, 4),
            stream_count: n as u32,
            timestamp: u32le(&h, 20),
            flags: u64le(&h, 24),
        };
        let dir = s.bytes(dir_rva, n * 12)?;
        let streams: Vec<StreamEntry> = (0..n as usize)
            .map(|i| StreamEntry {
                stream_type: u32le(&dir, i * 12),
                size: u32le(&dir, i * 12 + 4),
                rva: u32le(&dir, i * 12 + 8),
            })
            .filter(|e| e.stream_type != 0 && e.size != 0)
            .collect();
        let find = |t: u32| streams.iter().find(|e| e.stream_type == t).copied();

        let mut md = Minidump { header: Some(header), streams: streams.clone(), ..Default::default() };

        if let Some(e) = find(ST_SYSTEM_INFO) {
            let b = s.bytes(e.rva as u64, e.size.min(28) as u64)?;
            if b.len() >= 20 {
                md.system = Some(SystemInfo {
                    arch: u16le(&b, 0),
                    cpu_count: b[6],
                    major: u32le(&b, 8),
                    minor: u32le(&b, 12),
                    build: u32le(&b, 16),
                });
            }
        }
        if let Some(e) = find(ST_MISC_INFO) {
            let b = s.bytes(e.rva as u64, e.size.min(12) as u64)?;
            if b.len() >= 12 && u32le(&b, 4) & 1 != 0 {
                md.pid = Some(u32le(&b, 8));
            }
        }
        if let Some(e) = find(ST_MODULE_LIST) {
            let b = s.bytes(e.rva as u64, e.size as u64)?;
            let cnt = u32le(&b, 0) as usize;
            if 4 + cnt * 108 > b.len() {
                return Err(bad("module list truncated"));
            }
            for i in 0..cnt {
                let o = 4 + i * 108;
                let name = s.utf16_string(u32le(&b, o + 20) as u64).unwrap_or_default();
                md.modules.push(Module {
                    base: u64le(&b, o),
                    size: u32le(&b, o + 8),
                    timestamp: u32le(&b, o + 16),
                    name,
                });
            }
        }
        if let Some(e) = find(ST_THREAD_LIST) {
            let b = s.bytes(e.rva as u64, e.size as u64)?;
            let cnt = u32le(&b, 0) as usize;
            if 4 + cnt * 48 > b.len() {
                return Err(bad("thread list truncated"));
            }
            for i in 0..cnt {
                let o = 4 + i * 48;
                md.threads.push(Thread {
                    id: u32le(&b, o),
                    teb: u64le(&b, o + 16),
                    stack_start: u64le(&b, o + 24),
                    stack_size: u32le(&b, o + 32),
                });
            }
        }
        if let Some(e) = find(ST_MEMORY64_LIST) {
            let hdr = s.bytes(e.rva as u64, 16)?;
            let cnt = u64le(&hdr, 0);
            let mut off = u64le(&hdr, 8);
            let b = s.bytes(e.rva as u64 + 16, cnt.checked_mul(16).ok_or_else(|| bad("range count overflow"))?)?;
            for i in 0..cnt as usize {
                let start = u64le(&b, i * 16);
                let size = u64le(&b, i * 16 + 8);
                md.ranges.push(MemoryRange { start, size, file_offset: off });
                off = off.checked_add(size).ok_or_else(|| bad("range offset overflow"))?;
            }
            md.ranges.sort_by_key(|r| r.start);
        }
        if let Some(e) = find(ST_MEMORY_INFO_LIST) {
            let b = s.bytes(e.rva as u64, e.size as u64)?;
            let hs = u32le(&b, 0) as usize;
            let es = u32le(&b, 4) as usize;
            let cnt = u64le(&b, 8) as usize;
            if es < 48 || hs.checked_add(cnt.saturating_mul(es)).map_or(true, |t| t > b.len()) {
                return Err(bad("memory info list truncated"));
            }
            for i in 0..cnt {
                let o = hs + i * es;
                md.regions.push(MemoryRegion {
                    base: u64le(&b, o),
                    allocation_base: u64le(&b, o + 8),
                    size: u64le(&b, o + 24),
                    state: u32le(&b, o + 32),
                    protect: u32le(&b, o + 36),
                    kind: u32le(&b, o + 40),
                });
            }
        }
        Ok(md)
    }

    /// Virtual address -> offset inside the dump file (if captured).
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        let i = self.ranges.partition_point(|r| r.start <= va);
        let r = self.ranges.get(i.checked_sub(1)?)?;
        let d = va - r.start;
        (d < r.size).then(|| r.file_offset + d)
    }

    /// File offset -> virtual address (linear scan; ranges are few thousand).
    pub fn offset_to_va(&self, off: u64) -> Option<u64> {
        self.ranges
            .iter()
            .find(|r| off >= r.file_offset && off - r.file_offset < r.size)
            .map(|r| r.start + (off - r.file_offset))
    }

    pub fn module_for_va(&self, va: u64) -> Option<&Module> {
        self.modules.iter().find(|m| va >= m.base && va - m.base < m.size as u64)
    }

    pub fn region_for_va(&self, va: u64) -> Option<&MemoryRegion> {
        let i = self.regions.partition_point(|r| r.base <= va);
        let r = self.regions.get(i.checked_sub(1)?)?;
        (va - r.base < r.size).then_some(r)
    }

    /// Committed regions that are both writable and executable (triage signal).
    pub fn rwx_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.state == MemoryRegion::MEM_COMMIT && r.is_executable() && r.is_writable())
            .collect()
    }

    /// Render a Volatility-style tree. `max_items` caps each list.
    pub fn render_tree(&self, max_items: usize) -> String {
        let mut o = String::new();
        let pid = self.pid.map_or("?".to_string(), |p| p.to_string());
        match &self.system {
            Some(s) => {
                let _ = writeln!(o, "Process pid={pid} [{} | Windows {}.{}.{} | {} CPU]", s.arch_name(), s.major, s.minor, s.build, s.cpu_count);
            }
            None => {
                let _ = writeln!(o, "Process pid={pid}");
            }
        }
        let _ = writeln!(o, "|- Modules ({})", self.modules.len());
        for m in self.modules.iter().take(max_items) {
            let _ = writeln!(o, "|  |- {:#018x} +{:#08x} {}", m.base, m.size, m.name);
        }
        let _ = writeln!(o, "|- Threads ({})", self.threads.len());
        for t in self.threads.iter().take(max_items) {
            let _ = writeln!(o, "|  |- tid={} teb={:#x} stack={:#x}+{:#x}", t.id, t.teb, t.stack_start, t.stack_size);
        }
        let captured: u64 = self.ranges.iter().map(|r| r.size).sum();
        let _ = writeln!(o, "|- Memory ({} captured ranges, {:.1} MiB)", self.ranges.len(), captured as f64 / 1_048_576.0);
        let (mut c, mut r, mut f) = (0, 0, 0);
        for g in &self.regions {
            match g.state {
                MemoryRegion::MEM_COMMIT => c += 1,
                MemoryRegion::MEM_RESERVE => r += 1,
                MemoryRegion::MEM_FREE => f += 1,
                _ => {}
            }
        }
        let _ = writeln!(o, "|  |- regions: {} committed, {} reserved, {} free", c, r, f);
        let rwx = self.rwx_regions();
        let _ = writeln!(o, "|  `- RWX committed regions: {}", rwx.len());
        for g in rwx.iter().take(max_items) {
            let _ = writeln!(o, "|       |- {:#018x} +{:#x} {} {}", g.base, g.size, protect_name(g.protect), g.kind_name());
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn le32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn le64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    fn synth() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"MDMP");
        le32(&mut v, 0xa793);
        le32(&mut v, 3); // streams
        le32(&mut v, 32); // dir rva
        le32(&mut v, 0);
        le32(&mut v, 1);
        le64(&mut v, 0);
        let dir = v.len();
        v.resize(dir + 36, 0);
        // SystemInfo
        let sys = v.len();
        v.extend_from_slice(&9u16.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&[4, 1]);
        le32(&mut v, 10);
        le32(&mut v, 0);
        le32(&mut v, 26200);
        v.resize(sys + 56, 0);
        // module name + module list
        let name_rva = v.len();
        let units: Vec<u16> = "C:\\a.exe".encode_utf16().collect();
        le32(&mut v, (units.len() * 2) as u32);
        for u in &units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        let ml = v.len();
        le32(&mut v, 1);
        le64(&mut v, 0x1000);
        le32(&mut v, 0x2000);
        le32(&mut v, 0);
        le32(&mut v, 0);
        le32(&mut v, name_rva as u32);
        v.resize(ml + 4 + 108, 0);
        // Memory64List
        let m64 = v.len();
        le64(&mut v, 1);
        le64(&mut v, (m64 + 32) as u64);
        le64(&mut v, 0x1000);
        le64(&mut v, 16);
        let data_off = v.len();
        v.extend_from_slice(&[0xAA; 16]);
        assert_eq!(data_off, m64 + 32);
        for (i, (t, sz, rva)) in [(7u32, 56usize, sys), (4, 4 + 108, ml), (9, 48, m64)].iter().enumerate() {
            let d = dir + i * 12;
            v[d..d + 4].copy_from_slice(&t.to_le_bytes());
            v[d + 4..d + 8].copy_from_slice(&(*sz as u32).to_le_bytes());
            v[d + 8..d + 12].copy_from_slice(&(*rva as u32).to_le_bytes());
        }
        v
    }

    #[test]
    fn parses_synthetic_dump() {
        let bytes = synth();
        let md = Minidump::from_reader(Cursor::new(bytes)).unwrap();
        assert_eq!(md.system.as_ref().unwrap().build, 26200);
        assert_eq!(md.modules[0].name, "C:\\a.exe");
        let off = md.va_to_offset(0x1003).unwrap();
        assert_eq!(md.offset_to_va(off), Some(0x1003));
        assert!(md.va_to_offset(0x1010).is_none());
        assert_eq!(md.module_for_va(0x1800).unwrap().base, 0x1000);
        assert!(md.render_tree(5).contains("a.exe"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Minidump::from_reader(Cursor::new(vec![0u8; 64])).is_err());
    }
}

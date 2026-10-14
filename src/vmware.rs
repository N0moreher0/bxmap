//! Inspection of VMware suspend/snapshot state files (`.vmss` / `.vmsn`).
//!
//! The group table (header magic, group names, tag offsets) is parsed here and
//! the tag walker follows the layout used by public analysis tools. The tag
//! walker is best-effort: it stops at the first inconsistent tag instead of
//! guessing. Guest RAM is normally stored in a sibling `.vmem` file, which is
//! a flat physical-memory image that the regular string scanner can read as-is.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAGICS: [u32; 4] = [0xbed2_bed0, 0xbad1_bad1, 0xbed2_bed2, 0xbed3_bed3];
const MAX_GROUPS: u32 = 4096;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub tags_offset: u64,
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub name: String,
    pub indices: Vec<u32>,
    pub data_offset: u64,
    pub data_len: u64,
}

#[derive(Debug, Clone)]
pub struct VmwareState {
    pub path: PathBuf,
    pub magic: u32,
    pub groups: Vec<Group>,
}

fn read_exact_at(f: &mut File, off: u64, n: usize) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; n];
    f.read_exact(&mut b)?;
    Ok(b)
}

impl VmwareState {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;
        let len = f.metadata()?.len();
        let h = read_exact_at(&mut f, 0, 12)?;
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        if !MAGICS.contains(&magic) {
            return Err(bad("not a VMware state file (unknown magic)"));
        }
        let count = u32::from_le_bytes([h[8], h[9], h[10], h[11]]);
        if count > MAX_GROUPS || 12 + count as u64 * 80 > len {
            return Err(bad("implausible group count"));
        }
        let table = read_exact_at(&mut f, 12, count as usize * 80)?;
        let mut groups = Vec::new();
        for i in 0..count as usize {
            let e = &table[i * 80..(i + 1) * 80];
            let end = e[..64].iter().position(|&b| b == 0).unwrap_or(64);
            let mut off = [0u8; 8];
            off.copy_from_slice(&e[64..72]);
            groups.push(Group {
                name: String::from_utf8_lossy(&e[..end]).into_owned(),
                tags_offset: u64::from_le_bytes(off),
            });
        }
        Ok(Self { path, magic, groups })
    }

    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Walk up to `max` tags of a group. Stops quietly at the first tag that
    /// does not fit inside the file.
    pub fn tags(&self, group: &Group, max: usize) -> io::Result<Vec<Tag>> {
        let mut f = File::open(&self.path)?;
        let len = f.metadata()?.len();
        let mut pos = group.tags_offset;
        let mut out = Vec::new();
        while out.len() < max {
            if pos + 2 > len {
                break;
            }
            let h = read_exact_at(&mut f, pos, 2)?;
            let (flags, name_len) = (h[0], h[1] as u64);
            if flags == 0 {
                break;
            }
            pos += 2;
            let n_idx = ((flags >> 6) & 3) as u64;
            if pos + name_len + n_idx * 4 > len {
                break;
            }
            let name = read_exact_at(&mut f, pos, name_len as usize)?;
            pos += name_len;
            let mut indices = Vec::new();
            for _ in 0..n_idx {
                let b = read_exact_at(&mut f, pos, 4)?;
                indices.push(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                pos += 4;
            }
            let small = (flags & 0x3f) as u64;
            let (data_offset, data_len) = if small >= 62 {
                if pos + 8 > len {
                    break;
                }
                let b = read_exact_at(&mut f, pos, 8)?;
                let l = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                let pad = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
                pos += 8;
                (pos + pad, l)
            } else {
                (pos, small)
            };
            if data_offset + data_len > len {
                break;
            }
            out.push(Tag {
                name: String::from_utf8_lossy(&name).into_owned(),
                indices,
                data_offset,
                data_len,
            });
            pos = data_offset + data_len;
        }
        Ok(out)
    }

    /// Read the first (up to 8) data bytes of a tag as a little-endian u64.
    pub fn tag_u64(&self, tag: &Tag) -> io::Result<Option<u64>> {
        if tag.data_len < 8 {
            return Ok(None);
        }
        let mut f = File::open(&self.path)?;
        let b = read_exact_at(&mut f, tag.data_offset, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&b);
        Ok(Some(u64::from_le_bytes(a)))
    }

    /// The `.vmem` file next to this state file, if present.
    pub fn sibling_vmem(&self) -> Option<PathBuf> {
        let p = self.path.with_extension("vmem");
        p.is_file().then_some(p)
    }

    pub fn render_info(&self) -> String {
        use std::fmt::Write as _;
        let mut o = String::new();
        let _ = writeln!(o, "VMware state file: {}", self.path.display());
        let _ = writeln!(o, "|- magic {:#010x}, {} groups", self.magic, self.groups.len());
        for g in &self.groups {
            let _ = writeln!(o, "|  |- {:<24} tags@{:#x}", g.name, g.tags_offset);
        }
        match self.sibling_vmem() {
            Some(p) => {
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                let _ = writeln!(o, "|- RAM image: {} ({:.1} MiB, flat physical memory)", p.display(), size as f64 / 1_048_576.0);
            }
            None => {
                let _ = writeln!(o, "|- RAM image: no sibling .vmem (memory is probably inside this file)");
            }
        }
        if let Some(g) = self.group("memory") {
            if let Ok(tags) = self.tags(g, 40) {
                let _ = writeln!(o, "|- memory tags ({} shown)", tags.len());
                for t in &tags {
                    let _ = writeln!(o, "|  |- {} {:?} len={} @{:#x}", t.name, t.indices, t.data_len, t.data_offset);
                }
            }
        }
        if let Some(g) = self.group("cpu") {
            if let Ok(tags) = self.tags(g, 4000) {
                let _ = writeln!(o, "|- cpu control registers");
                for t in tags.iter().filter(|t| t.name.starts_with("CR")) {
                    if let Ok(Some(v)) = self.tag_u64(t) {
                        let _ = writeln!(o, "|  |- {} {:?} = {:#x}", t.name, t.indices, v);
                    }
                }
            }
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_group_table_and_tags() {
        let mut v = Vec::new();
        v.extend_from_slice(&0xbed2_bed2u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        let mut name = [0u8; 64];
        name[..6].copy_from_slice(b"memory");
        v.extend_from_slice(&name);
        let tags_off = (v.len() + 16) as u64;
        v.extend_from_slice(&tags_off.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        // tag: flags = 0 indices<<6 | 8 data bytes, name "abc"
        v.push(8);
        v.push(3);
        v.extend_from_slice(b"abc");
        v.extend_from_slice(&0x1122u64.to_le_bytes());
        v.push(0);
        v.push(0);
        let dir = std::env::temp_dir().join("bxmap_vmware_test.vmss");
        std::fs::File::create(&dir).unwrap().write_all(&v).unwrap();
        let st = VmwareState::open(&dir).unwrap();
        let g = st.group("memory").unwrap().clone();
        let tags = st.tags(&g, 10).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "abc");
        assert_eq!(st.tag_u64(&tags[0]).unwrap(), Some(0x1122));
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn rejects_unknown_magic() {
        let dir = std::env::temp_dir().join("bxmap_vmware_bad.vmss");
        std::fs::write(&dir, vec![0u8; 128]).unwrap();
        assert!(VmwareState::open(&dir).is_err());
        let _ = std::fs::remove_file(&dir);
    }
}

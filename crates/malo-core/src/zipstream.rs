//! A ZIP writer for archives sent while they're made: nothing is ever sought back to, so the
//! output can go straight into an HTTP response. Whole files are deflated (or stored, when that
//! is smaller) with their sizes in the local header; long files written piece by piece use a data
//! descriptor. ZIP64 records are added where offsets, sizes or the entry count need them, so an
//! export can exceed 4 GiB and 65,535 files.
//!
//! The caller drains [`ZipWriter::take`] as often as it likes; [`ZipWriter::finish`] returns the
//! rest, central directory included.

use std::io::Write;

use chrono::{DateTime, Datelike, Timelike, Utc};
use flate2::write::DeflateEncoder;
use flate2::Compression;

const LIMIT: u64 = 0xFFFF_FFFF;
const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
/// UTF-8 names.
const FLAG_UTF8: u16 = 1 << 11;
/// Sizes and CRC follow the data.
const FLAG_DESCRIPTOR: u16 = 1 << 3;
/// Unix, spec version 4.5.
const MADE_BY: u16 = (3 << 8) | 45;

struct Open {
    name: Vec<u8>,
    time: (u16, u16),
    offset: u64,
    crc: crc32fast::Hasher,
    size: u64,
    compressed: u64,
    enc: DeflateEncoder<Vec<u8>>,
}

pub struct ZipWriter {
    out: Vec<u8>,
    /// Bytes produced so far, drained or not.
    written: u64,
    central: Vec<u8>,
    entries: u64,
    open: Option<Open>,
    /// Tests: ZIP64 records even when nothing needs them.
    force64: bool,
}

impl Default for ZipWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// MS-DOS time and date, in UTC (ZIP has no time zone). Clamped to 1980–2107.
fn dos_time(t: DateTime<Utc>) -> (u16, u16) {
    if t.year() < 1980 {
        return (0, (1 << 5) | 1);
    }
    if t.year() > 2107 {
        return ((23 << 11) | (59 << 5) | 29, (127 << 9) | (12 << 5) | 31);
    }
    let time = (t.hour() << 11) | (t.minute() << 5) | (t.second() / 2);
    let date = ((t.year() as u32 - 1980) << 9) | (t.month() << 5) | t.day();
    (time as u16, date as u16)
}

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn u64le(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn clamp32(x: u64) -> u32 {
    x.min(LIMIT) as u32
}

impl ZipWriter {
    pub fn new() -> Self {
        ZipWriter {
            out: Vec::new(),
            written: 0,
            central: Vec::new(),
            entries: 0,
            open: None,
            force64: false,
        }
    }

    #[cfg(test)]
    fn forcing_zip64() -> Self {
        ZipWriter {
            force64: true,
            ..Self::new()
        }
    }

    /// Output not taken yet.
    pub fn pending(&self) -> usize {
        self.out.len()
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Bytes produced so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    fn emit(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
        self.written += b.len() as u64;
    }

    /// A central directory record. ZIP64 fields are added for values that don't fit.
    #[allow(clippy::too_many_arguments)]
    fn central_entry(
        &mut self,
        name: &[u8],
        flags: u16,
        method: u16,
        (time, date): (u16, u16),
        crc: u32,
        compressed: u64,
        size: u64,
        offset: u64,
        external: u32,
    ) {
        let mut extra = Vec::new();
        if size >= LIMIT || self.force64 {
            u64le(&mut extra, size);
        }
        if compressed >= LIMIT || self.force64 {
            u64le(&mut extra, compressed);
        }
        if offset >= LIMIT || self.force64 {
            u64le(&mut extra, offset);
        }
        let zip64 = !extra.is_empty();
        let force = self.force64;
        let big = |x: u64| if force { LIMIT as u32 } else { clamp32(x) };
        let c = &mut self.central;
        u32le(c, CENTRAL);
        u16le(c, MADE_BY);
        u16le(
            c,
            if zip64 || flags & FLAG_DESCRIPTOR != 0 {
                45
            } else {
                20
            },
        );
        u16le(c, flags);
        u16le(c, method);
        u16le(c, time);
        u16le(c, date);
        u32le(c, crc);
        u32le(c, big(compressed));
        u32le(c, big(size));
        u16le(c, name.len() as u16);
        u16le(c, if zip64 { extra.len() as u16 + 4 } else { 0 });
        u16le(c, 0); // comment
        u16le(c, 0); // disk
        u16le(c, 0); // internal attributes
        u32le(c, external);
        u32le(c, big(offset));
        c.extend_from_slice(name);
        if zip64 {
            u16le(c, 1);
            u16le(c, extra.len() as u16);
            c.extend_from_slice(&extra);
        }
        self.entries += 1;
    }

    fn check_name(name: &str) -> Vec<u8> {
        let name = name.trim_start_matches('/');
        let mut b = name.as_bytes().to_vec();
        b.truncate(0xFFFF);
        b
    }

    /// An empty directory (`name` ends with `/`).
    pub fn add_dir(&mut self, name: &str, time: DateTime<Utc>) {
        assert!(self.open.is_none(), "a file is still open");
        let mut name = Self::check_name(name);
        if !name.ends_with(b"/") {
            name.push(b'/');
        }
        let t = dos_time(time);
        let offset = self.written;
        let mut h = Vec::with_capacity(30 + name.len());
        u32le(&mut h, LOCAL);
        u16le(&mut h, 20);
        u16le(&mut h, FLAG_UTF8);
        u16le(&mut h, 0);
        u16le(&mut h, t.0);
        u16le(&mut h, t.1);
        u32le(&mut h, 0);
        u32le(&mut h, 0);
        u32le(&mut h, 0);
        u16le(&mut h, name.len() as u16);
        u16le(&mut h, 0);
        h.extend_from_slice(&name);
        self.emit(&h);
        self.central_entry(
            &name,
            FLAG_UTF8,
            0,
            t,
            0,
            0,
            0,
            offset,
            (0o40755 << 16) | 0x10,
        );
    }

    /// A whole file, deflated unless storing it is smaller. At most 4 GiB.
    pub fn add_file(&mut self, name: &str, time: DateTime<Utc>, data: &[u8]) {
        assert!(self.open.is_none(), "a file is still open");
        assert!((data.len() as u64) < LIMIT, "file too large for add_file");
        let name = Self::check_name(name);
        let t = dos_time(time);
        let crc = crc32fast::hash(data);
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        let deflated = enc.write_all(data).and_then(|()| enc.finish()).ok();
        let (method, body): (u16, &[u8]) = match &deflated {
            Some(d) if d.len() < data.len() => (8, d),
            _ => (0, data),
        };
        let offset = self.written;
        let mut h = Vec::with_capacity(30 + name.len());
        u32le(&mut h, LOCAL);
        u16le(&mut h, 20);
        u16le(&mut h, FLAG_UTF8);
        u16le(&mut h, method);
        u16le(&mut h, t.0);
        u16le(&mut h, t.1);
        u32le(&mut h, crc);
        u32le(&mut h, body.len() as u32);
        u32le(&mut h, data.len() as u32);
        u16le(&mut h, name.len() as u16);
        u16le(&mut h, 0);
        h.extend_from_slice(&name);
        self.emit(&h);
        let (blen, dlen) = (body.len() as u64, data.len() as u64);
        let body = body.to_vec();
        self.emit(&body);
        self.central_entry(
            &name,
            FLAG_UTF8,
            method,
            t,
            crc,
            blen,
            dlen,
            offset,
            0o100644 << 16,
        );
    }

    /// Starts a file of unknown length, written with [`ZipWriter::write`].
    pub fn start_file(&mut self, name: &str, time: DateTime<Utc>) {
        assert!(self.open.is_none(), "a file is still open");
        let name = Self::check_name(name);
        let t = dos_time(time);
        let offset = self.written;
        let mut h = Vec::with_capacity(50 + name.len());
        u32le(&mut h, LOCAL);
        u16le(&mut h, 45);
        u16le(&mut h, FLAG_UTF8 | FLAG_DESCRIPTOR);
        u16le(&mut h, 8);
        u16le(&mut h, t.0);
        u16le(&mut h, t.1);
        u32le(&mut h, 0);
        // ZIP64 sizes in the extra field, so the data descriptor carries 8-byte sizes.
        u32le(&mut h, LIMIT as u32);
        u32le(&mut h, LIMIT as u32);
        u16le(&mut h, name.len() as u16);
        u16le(&mut h, 20);
        h.extend_from_slice(&name);
        u16le(&mut h, 1);
        u16le(&mut h, 16);
        u64le(&mut h, 0);
        u64le(&mut h, 0);
        self.emit(&h);
        self.open = Some(Open {
            name,
            time: t,
            offset,
            crc: crc32fast::Hasher::new(),
            size: 0,
            compressed: 0,
            enc: DeflateEncoder::new(Vec::new(), Compression::default()),
        });
    }

    pub fn write(&mut self, data: &[u8]) {
        let open = self.open.as_mut().expect("no open file");
        open.crc.update(data);
        open.size += data.len() as u64;
        // Writing into a Vec can't fail.
        let _ = open.enc.write_all(data);
        let produced = std::mem::take(open.enc.get_mut());
        open.compressed += produced.len() as u64;
        self.emit(&produced);
    }

    pub fn finish_file(&mut self) {
        let mut open = self.open.take().expect("no open file");
        let rest = open.enc.finish().unwrap_or_default();
        open.compressed += rest.len() as u64;
        self.emit(&rest);
        let crc = open.crc.finalize();
        let mut d = Vec::with_capacity(24);
        u32le(&mut d, DESCRIPTOR);
        u32le(&mut d, crc);
        u64le(&mut d, open.compressed);
        u64le(&mut d, open.size);
        self.emit(&d);
        self.central_entry(
            &open.name,
            FLAG_UTF8 | FLAG_DESCRIPTOR,
            8,
            open.time,
            crc,
            open.compressed,
            open.size,
            open.offset,
            0o100644 << 16,
        );
    }

    /// The central directory and end records; returns what wasn't taken yet.
    pub fn finish(mut self) -> Vec<u8> {
        if self.open.is_some() {
            self.finish_file();
        }
        let start = self.written;
        let central = std::mem::take(&mut self.central);
        self.emit(&central);
        let size = central.len() as u64;
        let zip64 = self.force64 || self.entries >= 0xFFFF || start >= LIMIT || size >= LIMIT;
        let mut e = Vec::new();
        if zip64 {
            let at = self.written;
            u32le(&mut e, END64);
            u64le(&mut e, 44);
            u16le(&mut e, MADE_BY);
            u16le(&mut e, 45);
            u32le(&mut e, 0);
            u32le(&mut e, 0);
            u64le(&mut e, self.entries);
            u64le(&mut e, self.entries);
            u64le(&mut e, size);
            u64le(&mut e, start);
            u32le(&mut e, LOCATOR64);
            u32le(&mut e, 0);
            u64le(&mut e, at);
            u32le(&mut e, 1);
        }
        let count = if zip64 { 0xFFFF } else { self.entries as u16 };
        u32le(&mut e, END);
        u16le(&mut e, 0);
        u16le(&mut e, 0);
        u16le(&mut e, count);
        u16le(&mut e, count);
        u32le(&mut e, if zip64 { LIMIT as u32 } else { size as u32 });
        u32le(&mut e, if zip64 { LIMIT as u32 } else { start as u32 });
        u16le(&mut e, 0);
        self.emit(&e);
        self.out
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn read_back(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("valid zip");
        (0..z.len())
            .map(|i| {
                let mut f = z.by_index(i).unwrap();
                let mut data = vec![];
                f.read_to_end(&mut data).unwrap();
                (f.name().to_string(), data)
            })
            .collect()
    }

    fn sample(w: &mut ZipWriter, out: &mut Vec<u8>) {
        let t = DateTime::parse_from_rfc3339("2024-05-06T07:08:10Z")
            .unwrap()
            .with_timezone(&Utc);
        w.add_dir("Work/cur/", t);
        w.add_file("Work/cur/1.eml", t, &b"Subject: hi\r\n\r\n".repeat(50));
        out.extend(w.take());
        w.add_file("Ünïcode/x.bin", t, &[1, 2, 3]);
        w.start_file("Work.mbox", t);
        for i in 0..1000 {
            w.write(format!("From line {i}\n").as_bytes());
            if i % 100 == 0 {
                out.extend(w.take());
            }
        }
        w.finish_file();
        w.add_file("empty", t, b"");
    }

    #[test]
    fn readable_by_zip_readers() {
        for force in [false, true] {
            let mut w = if force {
                ZipWriter::forcing_zip64()
            } else {
                ZipWriter::new()
            };
            let mut out = vec![];
            sample(&mut w, &mut out);
            let total = w.written();
            out.extend(w.finish());
            assert!(out.len() as u64 > total);
            let files = read_back(out);
            let names: Vec<_> = files.iter().map(|f| f.0.as_str()).collect();
            assert_eq!(
                names,
                [
                    "Work/cur/",
                    "Work/cur/1.eml",
                    "Ünïcode/x.bin",
                    "Work.mbox",
                    "empty"
                ]
            );
            assert_eq!(files[1].1, b"Subject: hi\r\n\r\n".repeat(50));
            assert_eq!(files[2].1, [1, 2, 3]);
            let mbox = String::from_utf8(files[3].1.clone()).unwrap();
            assert!(mbox.starts_with("From line 0\n") && mbox.ends_with("From line 999\n"));
            assert!(files[4].1.is_empty());
        }
    }

    #[test]
    fn many_entries() {
        let mut w = ZipWriter::new();
        let t = Utc::now();
        for i in 0..70_000u32 {
            w.add_file(&format!("{i}"), t, &i.to_le_bytes());
        }
        let files = read_back(w.finish());
        assert_eq!(files.len(), 70_000);
        assert_eq!(files[69_999].1, 69_999u32.to_le_bytes());
    }

    #[test]
    fn dos_times() {
        let t = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(dos_time(t("1970-01-01T00:00:00Z")), (0, 33));
        let (time, date) = dos_time(t("2024-05-06T07:08:10Z"));
        assert_eq!((time >> 11, (time >> 5) & 63, (time & 31) * 2), (7, 8, 10));
        assert_eq!((date >> 9, (date >> 5) & 15, date & 31), (44, 5, 6));
    }
}

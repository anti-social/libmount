use std::ffi::{OsStr, OsString};
use std::io::{BufReader, BufRead, Read, Split, Error as IOError};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::borrow::Cow;

use libc::c_ulong;
use libc::{MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_SYNCHRONOUS};
use libc::{MS_MANDLOCK, MS_DIRSYNC, MS_NOATIME, MS_NODIRATIME};
use libc::{MS_RELATIME, MS_STRICTATIME};

#[derive(Debug)]
pub enum MountsParserError {
    Read(String, IOError),
    IncompleteRow(String),
    InvalidValue(String),
}

pub struct MountsParser<R: Read> {
    rows: Split<BufReader<R>>
}

impl<R: Read> MountsParser<R> {
    pub fn new(mounts_file: R) -> MountsParser<R> {
        MountsParser {
            rows: BufReader::new(mounts_file).split(b'\n'),
        }
    }
}

pub struct MountInfo {
    pub mount_id: c_ulong,
    pub parent_id: c_ulong,
    pub major: c_ulong,
    pub minor: c_ulong,
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub mount_options: OsString,
    pub optional_fields: OsString,
    pub fstype: OsString,
    pub mount_source: OsString,
    pub super_options: OsString,
}

impl MountInfo {
    pub fn get_flags(&self) -> c_ulong {
        let mut flags = 0 as c_ulong;
        for opt in self.mount_options.as_bytes().split(|c| *c == b',') {
            let opt = OsStr::from_bytes(opt);
            if opt == OsStr::new("ro") { flags |= MS_RDONLY }
            else if opt == OsStr::new("nosuid") { flags |= MS_NOSUID }
            else if opt == OsStr::new("nodev") { flags |= MS_NODEV }
            else if opt == OsStr::new("noexec") { flags |= MS_NOEXEC }
            else if opt == OsStr::new("mand") { flags |= MS_MANDLOCK }
            else if opt == OsStr::new("sync") { flags |= MS_SYNCHRONOUS }
            else if opt == OsStr::new("dirsync") { flags |= MS_DIRSYNC }
            else if opt == OsStr::new("noatime") { flags |= MS_NOATIME }
            else if opt == OsStr::new("nodiratime") { flags |= MS_NODIRATIME }
            else if opt == OsStr::new("relatime") { flags |= MS_RELATIME }
            else if opt == OsStr::new("strictatime") { flags |= MS_STRICTATIME }
        }
        flags
    }
}

macro_rules! itry {
    ( $e:expr ) => {
        {
            match $e {
                Ok(v) => v,
                Err(e) => return Some(Err(From::from(e))),
            }
        }
    };
}

impl<R: Read> Iterator for MountsParser<R> {
    type Item = Result<MountInfo, MountsParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rows.next() {
            Some(Ok(mut row)) => {
                if row.ends_with(&[b'\r']) {
                    let new_len = row.len() - 1;
                    row.truncate(new_len);
                }

                let invalid_format = || {
                    MountsParserError::IncompleteRow(format!("Expected more values"))
                };

                // Whitespaces are escaped in /proc/mounts
                let mut columns = row.split(|c| *c == b' ');
                let mount_id = itry!(parse_int(&mut columns, &row));
                let parent_id = itry!(parse_int(&mut columns, &row));
                let mut major_minor = itry!(columns.next().ok_or_else(&invalid_format))
                    .split(|c| *c == b':');
                let major = itry!(parse_int(&mut major_minor, &row));
                let minor = itry!(parse_int(&mut major_minor, &row));
                let root = itry!(parse_path(&mut columns, &row));
                let mount_point = itry!(parse_path(&mut columns, &row));
                let mount_options = itry!(parse_os_str(&mut columns, &row));
                let optional_fields = itry!(parse_os_str(&mut columns, &row));
                let separator = itry!(columns.next().ok_or_else(&invalid_format));
                assert_eq!(separator, b"-");
                let fstype = itry!(parse_os_str(&mut columns, &row));
                let mount_source = itry!(parse_os_str(&mut columns, &row));
                let super_options = itry!(parse_os_str(&mut columns, &row));

                Some(Ok(MountInfo {
                    mount_id: mount_id,
                    parent_id: parent_id,
                    major: major,
                    minor: minor,
                    root: root,
                    mount_point: mount_point,
                    mount_options: mount_options,
                    optional_fields: optional_fields,
                    fstype: fstype,
                    mount_source: mount_source,
                    super_options: super_options,
                }))
            },
            Some(Err(e)) => {
                Some(Err(MountsParserError::Read(format!("Error when reading mounts file"), e)))
            },
            None => None,
        }
    }
}

fn parse_os_str(columns: &mut Iterator<Item=&[u8]>, row: &[u8])
    -> Result<OsString, MountsParserError>
{
    let bytes = try!(columns.next()
        .ok_or_else(|| MountsParserError::IncompleteRow(
            format!("Expected more values in row: {:?}",
                String::from_utf8_lossy(row)))));
    let mut value = Cow::Borrowed(bytes);
    try!(unescape_octals(&mut value));
    Ok(OsString::from_vec(value.into_owned()))
}

fn parse_int(columns: &mut Iterator<Item=&[u8]>, row: &[u8])
    -> Result<c_ulong, MountsParserError>
{
    let col = try!(columns.next()
        .ok_or_else(|| MountsParserError::IncompleteRow(
            format!("Expected more values for row: {:?}",
                String::from_utf8_lossy(row))))
        .map(|v| String::from_utf8_lossy(v)));
    col.parse::<c_ulong>()
        .map_err(|_| MountsParserError::InvalidValue(
            format!("Cannot parse integer from {:?}: {:?}",
                col, String::from_utf8_lossy(row))))
}

fn parse_path(columns: &mut Iterator<Item=&[u8]>, row: &[u8])
    -> Result<PathBuf, MountsParserError>
{
    Ok(PathBuf::from(try!(parse_os_str(columns, row))))
}

fn unescape_octals(v: &mut Cow<[u8]>) -> Result<(), MountsParserError>{
    let mut i = 0;
    loop {
        if v[i] == b'\\' {
            let tail = v.to_mut().split_off(i);
            if tail.len() < 4 {
                return Err(MountsParserError::InvalidValue(format!("Invalid escaping")));
            }
            let oct = String::from_utf8_lossy(&tail[1..4]);
            let b = try!(u8::from_str_radix(&oct, 8)
                .map_err(|_| MountsParserError::InvalidValue(
                    format!("Expected octal number"))));
            v.to_mut().push(b);
            v.to_mut().extend_from_slice(&tail[4..]);
        }
        i += 1;
        if i >= v.len() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use std::io::Cursor;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use libc::{MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_RELATIME};

    use super::{MountsParser, MountsParserError};

    #[test]
    fn test_mount_info_parser_proc() {
        let content = "19 24 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info = parser.next().unwrap().unwrap();
        assert_eq!(mount_info.mount_id, 19);
        assert_eq!(mount_info.parent_id, 24);
        assert_eq!(mount_info.major, 0);
        assert_eq!(mount_info.minor, 4);
        assert_eq!(mount_info.root, Path::new("/"));
        assert_eq!(mount_info.mount_point, Path::new("/proc"));
        assert_eq!(mount_info.mount_options, OsStr::new("rw,nosuid,nodev,noexec,relatime"));
        assert_eq!(mount_info.optional_fields, OsStr::new("shared:12"));
        assert_eq!(mount_info.fstype, OsStr::new("proc"));
        assert_eq!(mount_info.mount_source, OsStr::new("proc"));
        assert_eq!(mount_info.super_options, OsStr::new("rw"));
        assert_eq!(mount_info.get_flags(), MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME);
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mount_info_parser_whitespaces() {
        let content = r"76 24 8:6 / /home/my\040super\046name rw,relatime shared:29 - ext4 /dev/sda1 rw,data=ordered";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info = parser.next().unwrap().unwrap();
        assert_eq!(mount_info.mount_id, 76);
        assert_eq!(mount_info.parent_id, 24);
        assert_eq!(mount_info.major, 8);
        assert_eq!(mount_info.minor, 6);
        assert_eq!(mount_info.root, Path::new("/"));
        assert_eq!(mount_info.mount_point, Path::new("/home/my super&name"));
        assert_eq!(mount_info.mount_options, OsStr::new("rw,relatime"));
        assert_eq!(mount_info.optional_fields, OsStr::new("shared:29"));
        assert_eq!(mount_info.fstype, OsStr::new("ext4"));
        assert_eq!(mount_info.mount_source, OsStr::new("/dev/sda1"));
        assert_eq!(mount_info.super_options, OsStr::new("rw,data=ordered"));
        assert_eq!(mount_info.get_flags(), MS_RELATIME);
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mounts_parser_non_utf8() {
        let content = b"22 24 0:19 / /\xff rw shared:5 - tmpfs tmpfs rw,mode=755";
        let reader = Cursor::new(&content[..]);
        let mut parser = MountsParser::new(reader);
        let mount_info = parser.next().unwrap().unwrap();
        assert_eq!(mount_info.mount_point, Path::new(OsStr::from_bytes(b"/\xff")));
        assert_eq!(mount_info.mount_options, OsStr::new("rw"));
        assert_eq!(mount_info.fstype, OsStr::new("tmpfs"));
        assert_eq!(mount_info.mount_source, OsStr::new("tmpfs"));
        assert_eq!(mount_info.get_flags(), 0);
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mounts_parser_crlf() {
        let content = "26 20 0:21 / /tmp rw shared:4 - tmpfs tmpfs rw\r\n\
                       27 22 0:22 / /tmp rw,nosuid,nodev shared:6 - tmpfs tmpfs rw\n";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info = parser.next().unwrap().unwrap();
        assert_eq!(mount_info.mount_point, Path::new("/tmp"));
        assert_eq!(mount_info.mount_options, OsStr::new("rw"));
        assert_eq!(mount_info.super_options, OsStr::new("rw"));
        assert_eq!(mount_info.get_flags(), 0);
        let mount_info = parser.next().unwrap().unwrap();
        assert_eq!(mount_info.mount_point, Path::new("/tmp"));
        assert_eq!(mount_info.mount_options, OsStr::new("rw,nosuid,nodev"));
        assert_eq!(mount_info.super_options, OsStr::new("rw"));
        assert_eq!(mount_info.get_flags(), MS_NOSUID | MS_NODEV);
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mount_info_parser_incomplete_row() {
        let content = "19 24 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info_res = parser.next().unwrap();
        assert!(mount_info_res.is_err());
        match mount_info_res {
            Err(MountsParserError::IncompleteRow(_)) => {}
            _ => panic!("Expected incomplete row error")
        }
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mount_info_parser_invalid_int() {
        let content = "19 24b 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info_res = parser.next().unwrap();
        assert!(mount_info_res.is_err());
        match mount_info_res {
            Err(MountsParserError::InvalidValue(_)) => {}
            _ => panic!("Expected invalid row error")
        }
        assert!(parser.next().is_none());
    }

    #[test]
    fn test_mount_info_parser_invalid_escape() {
        let content = "19 24 0:4 / /proc\\01 rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw";
        let reader = Cursor::new(content.as_bytes());
        let mut parser = MountsParser::new(reader);
        let mount_info_res = parser.next().unwrap();
        assert!(mount_info_res.is_err());
        match mount_info_res {
            Err(MountsParserError::InvalidValue(_)) => {}
            _ => panic!("Expected invalid row error")
        }
        assert!(parser.next().is_none());
    }
}

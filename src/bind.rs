use std::io;
use std::fmt;
use std::ptr::null;
use std::ffi::CString;
use std::path::Path;

use libc::mount;
use nix::mount as flags;

use {OSError, Error};
use util::{path_to_cstring, as_path};
use explain::{Explainable, exists, user};


/// A mount bind definition
///
/// By default bind mount is recursive (it's what you want most of the time).
///
/// Also recursive mounts can be used in user namespaces.
#[derive(Debug, Clone)]
pub struct BindMount {
    source: CString,
    target: CString,
    recursive: bool,
}

impl BindMount {
    /// Create a new, recursive bind mount
    ///
    /// You can disable recursion with a `non_recursive()` method
    pub fn new<A: AsRef<Path>, B: AsRef<Path>>(source: A, target: B)
        -> BindMount
    {
        BindMount {
            source: path_to_cstring(source.as_ref()),
            target: path_to_cstring(target.as_ref()),
            recursive: true,
        }
    }
    /// Toggle recursion
    pub fn recursive(mut self, flag: bool) -> BindMount {
        self.recursive = flag;
        self
    }

    /// Execute a bind mount
    pub fn bare_mount(self) -> Result<(), OSError> {
        let mut flags = flags::MS_BIND;
        if self.recursive {
            flags = flags | flags::MS_REC;
        }
        let rc = unsafe { mount(
                self.source.as_ptr(),
                self.target.as_ptr(),
                null(),
                flags.bits(),
                null()) };
        if rc < 0 {
            Err(OSError(io::Error::last_os_error(), Box::new(self)))
        } else {
            Ok(())
        }
    }

    /// Execute a bind mount and explain the error immediately
    pub fn mount(self) -> Result<(), Error> {
        self.bare_mount().map_err(OSError::explain)
    }
}

impl fmt::Display for BindMount {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.recursive {
            try!(write!(fmt, "recursive "));
        }
        write!(fmt, "bind mount {:?} -> {:?}",
            as_path(&self.source), as_path(&self.target))
    }
}

impl Explainable for BindMount {
    fn explain(&self) -> String {
        [
            format!("source: {}", exists(as_path(&self.source))),
            format!("target: {}", exists(as_path(&self.target))),
            format!("{}", user()),
        ].join(", ")
    }
}


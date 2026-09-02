use std::ffi::CString;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::{null, null_mut};

use libkrb5_sys::*;

use crate::error::Krb5Error;

/// An MIT krb5 profile (a `krb5.conf`-shaped configuration) loaded from a file.
///
/// Combined with [`crate::Krb5Context::init_with_profile`], this lets
/// callers build a Kerberos context from an explicit configuration file
/// path, bypassing the default `/etc/krb5.conf` lookup. This is useful
/// when a service needs to guarantee that a specific configuration is
/// in effect regardless of what a system-wide `krb5.conf` might say.
///
/// A future extension may add an in-memory profile constructor
/// (`from_string`) for configurations that vary per connection.
pub struct Krb5Profile {
    handle: profile_t,
}

impl Krb5Profile {
    /// Load a profile from a `krb5.conf`-shaped file at `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Krb5Error> {
        let cpath = CString::new(path.as_ref().as_os_str().as_encoded_bytes()).map_err(|_| {
            Krb5Error::LibraryError {
                message: "profile path contains an interior NUL byte".to_string(),
            }
        })?;
        let mut files: [*const c_char; 2] = [cpath.as_ptr(), null()];

        let mut handle: profile_t = null_mut();
        // SAFETY: files is a NULL-terminated array of valid C strings;
        // handle is a valid out pointer. profile_init does not modify
        // the array despite the non-const signature.
        let code = unsafe { profile_init(files.as_mut_ptr(), &mut handle) };

        if code != 0 || handle.is_null() {
            return Err(Krb5Error::LibraryError {
                message: format!(
                    "profile_init failed: path={:?}, code={}, handle_null={}",
                    path.as_ref(),
                    code,
                    handle.is_null()
                ),
            });
        }

        Ok(Krb5Profile { handle })
    }

    pub(crate) fn as_ptr(&self) -> profile_t {
        self.handle
    }
}

impl Drop for Krb5Profile {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle was returned by profile_init and has not been
            // released elsewhere. krb5_init_context_profile duplicates the
            // profile internally (via krb5int_dup_profile), so releasing
            // our copy here is safe even if the profile was passed to a
            // Krb5Context.
            unsafe { profile_release(self.handle) };
            self.handle = null_mut();
        }
    }
}

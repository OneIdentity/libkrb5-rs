use core::slice;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::strconv::string_to_c_string;
use crate::{Krb5Context, Krb5Principal};
use libkrb5_sys::*;

pub struct Krb5Keytab {
    pub(crate) context: Krb5Context,
    pub(crate) keytab: krb5_keytab,
}

impl Drop for Krb5Keytab {
    fn drop(&mut self) {
        unsafe {
            krb5_kt_close(self.context.get_context(), self.keytab);
        }
    }
}

impl Krb5Keytab {
    pub fn new(context: &Krb5Context, keytab_path: &str) -> Result<Krb5Keytab, Krb5Error> {
        let mut keytab_ptr: MaybeUninit<krb5_keytab> = MaybeUninit::zeroed();
        let keytab_path = string_to_c_string(keytab_path)?;
        let code: krb5_error_code =
            unsafe { krb5_kt_resolve(context.get_context(), keytab_path.as_ptr(), keytab_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&context, code)?;

        let keytab = Krb5Keytab {
            context: context.clone(),
            keytab: unsafe { keytab_ptr.assume_init() },
        };

        Ok(keytab)
    }
}

pub struct Krb5Creds {
    pub(crate) context: Krb5Context,
    pub(crate) creds: krb5_creds,
}

impl Krb5Creds {
    pub fn get_init_creds_keytab(
        context: &Krb5Context,
        keytab: &Krb5Keytab,
        principal: &Krb5Principal,
    ) -> Result<Krb5Creds, Krb5Error> {
        let mut creds_ptr: MaybeUninit<krb5_creds> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_get_init_creds_keytab(
                context.get_context(),
                creds_ptr.as_mut_ptr(),
                principal.principal,
                keytab.keytab,
                0,
                null_mut(),
                null_mut(),
            )
        };

        krb5_error_code_escape_hatch(&context, code)?;

        let creds = Krb5Creds {
            context: context.clone(),
            creds: unsafe { creds_ptr.assume_init() },
        };

        Ok(creds)
    }

    pub fn get_init_creds_password(
        context: &Krb5Context,
        password: &str,
        principal: &Krb5Principal,
    ) -> Result<Krb5Creds, Krb5Error> {
        let mut creds_ptr: MaybeUninit<krb5_creds> = MaybeUninit::zeroed();
        let password = string_to_c_string(password)?;
        let code = unsafe {
            krb5_get_init_creds_password(
                context.get_context(),
                creds_ptr.as_mut_ptr(),
                principal.principal,
                password.as_ptr(),
                None,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
            )
        };

        krb5_error_code_escape_hatch(&context, code)?;

        let creds = Krb5Creds {
            context: context.clone(),
            creds: unsafe { creds_ptr.assume_init() },
        };

        Ok(creds)
    }

    pub fn ticket(&self) -> Option<&[u8]> {
        if self.creds.ticket.data.is_null() {
            return None;
        }

        let ticket =
            unsafe { slice::from_raw_parts(self.creds.ticket.data as *mut u8, self.creds.ticket.length as usize) };
        Some(ticket)
    }

    pub fn keyblock(&mut self) -> Result<Krb5Keyblock, Krb5Error> {
        Krb5Keyblock::new_from_raw(&self.context, &mut self.creds.keyblock)
    }

    pub fn get_client_principal(&self) -> Result<Krb5Principal, Krb5Error> {
        let mut out_princ: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
        let code =
            unsafe { krb5_copy_principal(self.context.get_context(), self.creds.client, out_princ.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let client_princ = Krb5Principal {
            context: self.context.clone(),
            principal: unsafe { out_princ.assume_init() },
        };

        Ok(client_princ)
    }

    pub fn set_server_principal(&mut self, principal: &Krb5Principal) -> Result<(), Krb5Error> {
        // Free the old server principal before overwriting to prevent a leak
        // (krb5_get_init_creds_password allocates a server principal like krbtgt/REALM)
        if !self.creds.server.is_null() {
            unsafe { krb5_free_principal(self.context.get_context(), self.creds.server) };
        }

        self.creds.server = principal.clone_into_raw()?;
        Ok(())
    }

    pub fn clone(&self) -> Result<Self, Krb5Error> {
        let mut out_creds: MaybeUninit<*mut krb5_creds> = MaybeUninit::zeroed();
        let code = unsafe { krb5_copy_creds(self.context.get_context(), &self.creds, out_creds.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let out_creds_ptr = unsafe { out_creds.assume_init() };
        let out_creds = Krb5Creds {
            context: self.context.clone(),
            creds: unsafe { *out_creds_ptr },
        };

        // Memory for the new krb5_creds struct is allocated by krb5_copy_creds. At this point
        // Krb5Creds gains ownership of the content, but not the whole struct, thus we
        // still have to free it.
        unsafe { libc::free(out_creds_ptr as *mut libc::c_void) };

        Ok(out_creds)
    }
}

impl Drop for Krb5Creds {
    fn drop(&mut self) {
        unsafe {
            krb5_free_cred_contents(self.context.get_context(), &mut self.creds);
        }
    }
}

pub struct Krb5Keyblock<'a> {
    pub(crate) context: Krb5Context,
    pub(crate) keyblock: &'a mut krb5_keyblock,
}

impl<'a> Drop for Krb5Keyblock<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_keyblock(self.context.get_context(), self.keyblock);
        }
    }
}

impl<'a> Krb5Keyblock<'a> {
    pub fn copy(&self) -> Result<Self, Krb5Error> {
        Krb5Keyblock::new_from_raw(&self.context, self.keyblock)
    }

    pub fn new_from_raw(context: &Krb5Context, from: *const krb5_keyblock) -> Result<Krb5Keyblock<'a>, Krb5Error> {
        let mut keyblock_ptr: MaybeUninit<*mut krb5_keyblock> = MaybeUninit::zeroed();
        let code = unsafe { krb5_copy_keyblock(context.get_context(), from, keyblock_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&context, code)?;

        let keyblock = Krb5Keyblock {
            context: context.clone(),
            keyblock: unsafe { &mut *keyblock_ptr.assume_init() },
        };
        Ok(keyblock)
    }
}

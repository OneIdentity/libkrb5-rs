use core::slice;
use std::mem::MaybeUninit;
use std::ptr::{null_mut};

use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::strconv::{string_to_c_string};
use crate::{Krb5Context, Krb5Principal};
use libkrb5_sys::*;

pub struct Krb5Keytab<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) keytab: krb5_keytab,
}

impl<'a> Drop for Krb5Keytab<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_kt_close(self.context.context, self.keytab);
        }
    }
}

impl<'a> Krb5Keytab<'a> {
    pub fn new(context: &'a Krb5Context, keytab_path: &str) -> Result<Krb5Keytab<'a>, Krb5Error> {
        let mut keytab_ptr: MaybeUninit<krb5_keytab> = MaybeUninit::zeroed();
        let keytab_path = string_to_c_string(keytab_path)?;
        let code: krb5_error_code =
            unsafe { krb5_kt_resolve(context.context, keytab_path.as_ptr(), keytab_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(context, code)?;

        let keytab = Krb5Keytab {
            context: &context,
            keytab: unsafe { keytab_ptr.assume_init() },
        };

        Ok(keytab)
    }
}

pub struct Krb5Creds<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) creds: krb5_creds,
}

impl<'a> Krb5Creds<'a> {
    pub fn get_init_creds_keytab(
        context: &'a Krb5Context,
        keytab: &Krb5Keytab,
        principal: &Krb5Principal,
    ) -> Result<Krb5Creds<'a>, Krb5Error> {
        let mut creds_ptr: MaybeUninit<krb5_creds> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_get_init_creds_keytab(
                context.context,
                creds_ptr.as_mut_ptr(),
                principal.principal,
                keytab.keytab,
                0,
                null_mut(),
                null_mut(),
            )
        };

        krb5_error_code_escape_hatch(context, code)?;

        let creds = Krb5Creds {
            context: &context,
            creds: unsafe { creds_ptr.assume_init() },
        };

        Ok(creds)
    }

    pub fn get_init_creds_password(
        context: &'a Krb5Context,
        password: &str,
        principal: &Krb5Principal,
    ) -> Result<Krb5Creds<'a>, Krb5Error> {
        let mut creds_ptr: MaybeUninit<krb5_creds> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_get_init_creds_password(
                context.context,
                creds_ptr.as_mut_ptr(),
                principal.principal,
                password.as_ptr() as *const i8,
                None,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
            )
        };

        krb5_error_code_escape_hatch(context, code)?;

        let creds = Krb5Creds {
            context: &context,
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
        let code = unsafe { krb5_copy_principal(self.context.context, self.creds.client, out_princ.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self.context, code)?;

        let client_princ = Krb5Principal {
            context: &self.context,
            principal: unsafe { out_princ.assume_init() },
        };

        Ok(client_princ)
    }

    pub fn clone(&self) -> Result<Self, Krb5Error> {
        let mut out_creds: MaybeUninit<*mut krb5_creds> = MaybeUninit::zeroed();
        let code = unsafe { krb5_copy_creds(self.context.context, &self.creds, out_creds.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self.context, code)?;

        let out_creds = Krb5Creds {
            context: &self.context,
            creds: unsafe { *out_creds.assume_init() },
        };

        Ok(out_creds)
    }
}

impl<'a> Drop for Krb5Creds<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_cred_contents(self.context.context, &mut self.creds);
        }
    }
}

pub struct Krb5Keyblock<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) keyblock: &'a mut krb5_keyblock,
}

impl<'a> Drop for Krb5Keyblock<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_keyblock(self.context.context, self.keyblock);
        }
    }
}

impl<'a> Krb5Keyblock<'a> {
    pub fn copy(&self) -> Result<Self, Krb5Error> {
        let mut keyblock_ptr: MaybeUninit<*mut krb5_keyblock> = MaybeUninit::zeroed();
        let code = unsafe {krb5_copy_keyblock(self.context.context, self.keyblock, keyblock_ptr.as_mut_ptr())};
        krb5_error_code_escape_hatch(self.context, code)?;

        let keyblock = Krb5Keyblock {
            context: self.context,
            keyblock: unsafe {
                keyblock_ptr.assume_init().as_mut().unwrap()
            }
        };

        Ok(keyblock)
    }

    pub fn new_from_raw(context: &'a Krb5Context, from: *mut krb5_keyblock) -> Result<Krb5Keyblock<'a>, Krb5Error> {
        let mut keyblock_ptr: MaybeUninit<*mut krb5_keyblock> = MaybeUninit::zeroed();
        let code = unsafe {krb5_copy_keyblock(context.context, from, keyblock_ptr.as_mut_ptr())};
        krb5_error_code_escape_hatch(&context, code)?;

        let keyblock = Krb5Keyblock {
            context: &context,
            keyblock: unsafe {&mut *keyblock_ptr.assume_init()}
        };
        Ok(keyblock)
    }
}

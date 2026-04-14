use std::mem::MaybeUninit;
use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::credential::Krb5Creds;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::strconv::{c_string_to_string, string_to_c_string};

#[derive(Debug)]
pub struct Krb5CCache {
    pub(crate) context: Krb5Context,
    pub(crate) ccache: krb5_ccache,
}

impl Drop for Krb5CCache {
    fn drop(&mut self) {
        unsafe {
            krb5_cc_destroy(self.context.get_context(), self.ccache);
        }
    }
}

impl Krb5CCache {
    pub fn default(context: &Krb5Context) -> Result<Krb5CCache, Krb5Error> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cc_default(context.get_context(), ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&context, code)?;

        let cursor = Krb5CCache {
            context: context.clone(),
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
    }

    pub fn default_name(context: &Krb5Context) -> Result<String, Krb5Error> {
        let name: *const c_char = unsafe { krb5_cc_default_name(context.get_context()) };

        c_string_to_string(name)
    }

    pub fn destroy(self) -> Result<(), Krb5Error> {
        let code = unsafe { krb5_cc_destroy(self.context.get_context(), self.ccache) };

        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(())
    }

    pub fn dup(&self) -> Result<Krb5CCache, Krb5Error> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cc_dup(self.context.get_context(), self.ccache, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&self.context, code)?;

        let ccache = Krb5CCache {
            context: self.context.clone(),
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(ccache)
    }

    pub fn get_name(&self) -> Result<String, Krb5Error> {
        let name: *const c_char = unsafe { krb5_cc_get_name(self.context.get_context(), self.ccache) };

        c_string_to_string(name)
    }

    pub fn get_principal(&self) -> Result<Option<Krb5Principal>, Krb5Error> {
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cc_get_principal(self.context.get_context(), self.ccache, principal_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&self.context, code)?;

        let principal_ptr = unsafe { principal_ptr.assume_init() };

        if principal_ptr.is_null() {
            return Ok(None);
        }

        let principal = Krb5Principal {
            context: self.context.clone(),
            principal: principal_ptr,
        };

        Ok(Some(principal))
    }

    pub fn get_type(&self) -> Result<String, Krb5Error> {
        let cctype: *const c_char = unsafe { krb5_cc_get_type(self.context.get_context(), self.ccache) };

        c_string_to_string(cctype)
    }

    pub fn initialize(&mut self, principal: &Krb5Principal) -> Result<(), Krb5Error> {
        let code: krb5_error_code =
            unsafe { krb5_cc_initialize(self.context.get_context(), self.ccache, principal.principal) };

        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(())
    }

    pub fn store(&self, creds: &Krb5Creds) -> Result<(), Krb5Error> {
        let mut creds = creds.clone()?;
        let code: krb5_error_code =
            unsafe { krb5_cc_store_cred(self.context.get_context(), self.ccache, &mut creds.creds) };

        krb5_error_code_escape_hatch(&self.context, code)?;
        Ok(())
    }

    pub fn new_unique(context: &Krb5Context, cctype: &str) -> Result<Krb5CCache, Krb5Error> {
        let cctype = string_to_c_string(cctype)?;

        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe {
            krb5_cc_new_unique(
                context.get_context(),
                cctype.as_ptr(),
                std::ptr::null(),
                ccache_ptr.as_mut_ptr(),
            )
        };

        krb5_error_code_escape_hatch(&context, code)?;

        let cursor = Krb5CCache {
            context: context.clone(),
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
    }

    pub fn resolve(context: &Krb5Context, name: &str) -> Result<Krb5CCache, Krb5Error> {
        let name = string_to_c_string(name)?;

        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cc_resolve(context.get_context(), name.as_ptr(), ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&context, code)?;

        let cursor = Krb5CCache {
            context: context.clone(),
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
    }
}

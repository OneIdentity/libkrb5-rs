use std::mem::MaybeUninit;

use libkrb5_sys::*;

use crate::ccache::Krb5CCache;
use crate::context::Krb5Context;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};

#[derive(Debug)]
pub struct Krb5CCCol {
    pub(crate) context: Krb5Context,
    pub(crate) cursor: krb5_cccol_cursor,
}

impl Krb5CCCol {
    pub fn new(context: &Krb5Context) -> Result<Krb5CCCol, Krb5Error> {
        let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.get_context(), cursor_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&context, code)?;

        let cursor = Krb5CCCol {
            context: context.clone(),
            cursor: unsafe { cursor_ptr.assume_init() },
        };

        Ok(cursor)
    }
}

impl Drop for Krb5CCCol {
    fn drop(&mut self) {
        unsafe {
            krb5_cccol_cursor_free(self.context.get_context(), &mut self.cursor);
        }
    }
}

impl Iterator for Krb5CCCol {
    type Item = Result<Krb5CCache, Krb5Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cccol_cursor_next(self.context.get_context(), self.cursor, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(&self.context, code).ok()?;

        let ccache_ptr = unsafe { ccache_ptr.assume_init() };

        if ccache_ptr.is_null() {
            return None;
        }

        let ccache = Krb5CCache {
            context: self.context.clone(),
            ccache: ccache_ptr,
        };

        Some(Ok(ccache))
    }
}

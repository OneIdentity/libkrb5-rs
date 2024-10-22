use std::mem::MaybeUninit;
use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::strconv::c_string_to_string;

#[derive(Debug)]
pub struct Krb5Principal<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) principal: krb5_principal,
}

impl<'a> Drop for Krb5Principal<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_principal(self.context.context, self.principal);
        }
    }
}

impl<'a> Krb5Principal<'a> {
    pub fn new_from_raw(context: &Krb5Context, raw_principal: krb5_principal) -> Result<Krb5Principal, Krb5Error> {
        let mut out_principal: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
        let code = unsafe { krb5_copy_principal(context.context, raw_principal, out_principal.as_mut_ptr()) };
        krb5_error_code_escape_hatch(context, code)?;

        let out_principal = Krb5Principal {
            context,
            principal: unsafe { out_principal.assume_init() },
        };
        Ok(out_principal)
    }

    pub fn data(&self) -> Krb5PrincipalData {
        Krb5PrincipalData {
            context: &self.context,
            principal_data: unsafe { *self.principal },
        }
    }
}

#[derive(Debug)]
pub struct Krb5PrincipalData<'a> {
    #[allow(dead_code)]
    pub(crate) context: &'a Krb5Context,
    pub(crate) principal_data: krb5_principal_data,
}

impl<'a> Krb5PrincipalData<'a> {
    pub fn realm(&self) -> Result<String, Krb5Error> {
        let realm: *const c_char = self.principal_data.realm.data;

        c_string_to_string(realm)
    }

    pub fn set_type(&mut self, type_: krb5_int32) {
        self.principal_data.type_ = type_
    }

    pub fn unparse(&mut self) -> Result<Option<String>, Krb5Error> {
        let mut name: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();
        let code: krb5_error_code =
            unsafe { krb5_unparse_name(self.context.context, &self.principal_data, name.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let name = unsafe { name.assume_init() };
        let string = c_string_to_string(name)?;
        unsafe { krb5_free_unparsed_name(self.context.context, name) };

        Ok(Some(string))
    }

    pub fn compare(&mut self, principal_data: Krb5PrincipalData) -> bool {
        let result = unsafe {
            krb5_principal_compare(
                self.context.context,
                &self.principal_data,
                &principal_data.principal_data,
            )
        };
        result != 0
    }
}

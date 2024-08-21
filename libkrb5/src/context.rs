use core::slice;
use std::mem::ManuallyDrop;
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::Mutex;
use bitflags::bitflags;

use lazy_static::lazy_static;
use libkrb5_sys::*;

use crate::credential::Krb5Keyblock;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::strconv::{c_string_to_string, string_to_c_string};

pub use libkrb5_sys::{
    KRB5_AUTH_CONTEXT_DO_SEQUENCE, KRB5_AUTH_CONTEXT_DO_TIME, KRB5_AUTH_CONTEXT_PERMIT_ALL,
    KRB5_AUTH_CONTEXT_RET_SEQUENCE, KRB5_AUTH_CONTEXT_RET_TIME, KRB5_AUTH_CONTEXT_USE_SUBKEY,
};

lazy_static! {
    static ref CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());
}

const TOK_MIC_MSG: u16 = 0x0404;

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Krb5KeyUsage {
    AcceptorSeal = 22,
    AcceptorSign = 23,
    InitiatorSeal = 24,
    InitiatorSign = 25,
}


bitflags! {
    pub struct Krb5TokenFlag: u8 {
        const SentByAcceptor = 1;
        const Sealed = 2;
        const AcceptorSubkey = 4;
    }
}

#[derive(Debug)]
pub struct Krb5Context {
    pub(crate) context: krb5_context,
}

impl Krb5Context {
    pub fn init() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    pub fn init_secure() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    pub fn build_principal<'a>(&'a self, realm: &'a str, args: &'a [String]) -> Result<Krb5Principal<'a>, Krb5Error> {
        let crealm = string_to_c_string(realm)?;
        let realml = realm.len() as u32;

        let mut varargs = Vec::new();
        for arg in args {
            varargs.push(string_to_c_string(arg)?);
        }

        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
        // TODO: write a macro to generate this match block
        let code: krb5_error_code = match args.len() {
            // varargs support in Rust is lacking, so only support a limited number of arguments for now
            0 => unsafe { krb5_build_principal(self.context, principal_ptr.as_mut_ptr(), realml, crealm.as_ptr()) },
            1 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm.as_ptr(),
                    varargs[0].as_ptr(),
                    std::ptr::null::<*const c_char>(),
                )
            },
            2 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm.as_ptr(),
                    varargs[0].as_ptr(),
                    varargs[1].as_ptr(),
                    std::ptr::null::<*const c_char>(),
                )
            },
            3 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm.as_ptr(),
                    varargs[0].as_ptr(),
                    varargs[1].as_ptr(),
                    varargs[2].as_ptr(),
                    std::ptr::null::<*const c_char>(),
                )
            },
            4 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm.as_ptr(),
                    varargs[0].as_ptr(),
                    varargs[1].as_ptr(),
                    varargs[2].as_ptr(),
                    varargs[3].as_ptr(),
                    std::ptr::null::<*const c_char>(),
                )
            },
            _ => return Err(Krb5Error::MaxVarArgsExceeded),
        };

        krb5_error_code_escape_hatch(self, code)?;

        let principal = Krb5Principal {
            context: self,
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    pub fn parse_principal(&self, name: &str) -> Result<Krb5Principal, Krb5Error> {
        let c_name = string_to_c_string(name)?;
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        let code = unsafe { krb5_parse_name(self.context, c_name.as_ptr(), principal_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let principal = Krb5Principal {
            context: self,
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    pub fn get_default_realm(&self) -> Result<Option<String>, Krb5Error> {
        let mut realm: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_get_default_realm(self.context, realm.as_mut_ptr()) };

        if code == KRB5_CONFIG_NODEFREALM {
            return Ok(None);
        }

        krb5_error_code_escape_hatch(self, code)?;

        let realm = unsafe { realm.assume_init() };

        let string = c_string_to_string(realm)?;
        unsafe { krb5_free_default_realm(self.context, realm) };

        Ok(Some(string))
    }

    pub fn get_host_realms(&self, host: Option<&str>) -> Result<Vec<String>, Krb5Error> {
        let c_host = string_to_c_string(host.unwrap_or(""))?;

        let c_host_ptr = if c_host.is_empty() {
            std::ptr::null()
        } else {
            c_host.as_ptr()
        };

        let mut c_realms: MaybeUninit<*mut *mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_get_host_realm(self.context, c_host_ptr, c_realms.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let c_realms = unsafe { c_realms.assume_init() };

        let mut realms: Vec<String> = Vec::new();
        let mut index: isize = 0;
        loop {
            let ptr = unsafe { *c_realms.offset(index) };

            if ptr.is_null() {
                break;
            }

            realms.push(c_string_to_string(ptr)?);

            index += 1;
        }

        unsafe { krb5_free_host_realm(self.context, c_realms) };

        Ok(realms)
    }

    pub fn verify_ap_req<'a>(
        &self,
        auth_context: &'a mut Krb5AuthContext,
        ap_req: &'a [u8],
        server: &'a Krb5Principal,
    ) -> Result<(i32, Krb5Ticket), Krb5Error> {
        let data = krb5_data {
            magic: 0,
            data: ap_req.as_ptr() as *mut i8,
            length: ap_req.len() as u32,
        };
        let mut ap_req_options: krb5_flags = 0;
        let mut ticket_ptr: MaybeUninit<*mut krb5_ticket> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_rd_req(
                self.context,
                &mut auth_context.auth_context,
                &data,
                server.principal,
                std::ptr::null_mut(),
                &mut ap_req_options,
                ticket_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let ticket = Krb5Ticket {
            context: self,
            ticket: unsafe { ticket_ptr.assume_init() },
        };

        Ok((ap_req_options, ticket))
    }

    pub fn create_ap_rep<'a>(&self, auth_context: &'a Krb5AuthContext) -> Result<&[u8], Krb5Error> {
        let mut ap_rep_ptr: MaybeUninit<krb5_data> = MaybeUninit::zeroed();
        let code = unsafe { krb5_mk_rep(self.context, auth_context.auth_context, ap_rep_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let ap_rep_ptr = unsafe { ap_rep_ptr.assume_init() };
        let ap_rep = unsafe { slice::from_raw_parts(ap_rep_ptr.data as *mut u8, ap_rep_ptr.length as usize) };

        Ok(ap_rep)
    }

    pub fn create_signature(
        &self,
        message_to_sign: &[u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
        local_seq_num: i32,
    ) -> Result<Vec<u8>, Krb5Error> {
        let header = Krb5Context::create_mic_token_header(usage, local_seq_num);
        let mut input_buf = [message_to_sign, header.as_slice()].concat();

        let checksum = self.create_checksum(input_buf.as_mut_slice(), key, usage).unwrap();

        let mic_token = [header.as_slice(), checksum].concat();
        Ok(mic_token)
    }

    pub fn verify_signature(&self, message: &[u8], mic: &[u8], key: &Krb5Keyblock, usage: Krb5KeyUsage, seq_num: i32) -> Result<(), Krb5Error> {
        let received_header = mic[0..16].to_vec();
        let received_checksum = &mic[16..];

        let expected_header = Krb5Context::create_mic_token_header(usage, seq_num);

        if received_header != expected_header {
            return Err(Krb5Error::InvalidToken)
        }

        let mut input_buf = [message, &received_header].concat();
        let expected_checksum = self.create_checksum(&mut input_buf, key, usage).unwrap();

        if received_checksum != expected_checksum {
            return Err(Krb5Error::InvalidToken);
        }

        Ok(())
    }

    pub fn create_checksum(&self, input_buf: &mut [u8], key: &Krb5Keyblock, usage: Krb5KeyUsage) -> Result<&[u8], Krb5Error> {
        let input_data = krb5_data {
            magic: 0,
            data: input_buf.as_mut_ptr() as *mut i8,
            length: input_buf.len() as u32,
        };

        let mut key = key.to_owned();
        let mut checksum_ptr: MaybeUninit<krb5_checksum> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_c_make_checksum(
                self.context,
                0,
                key.to_c(),
                usage as i32,
                &input_data,
                checksum_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let checksum_ptr = unsafe { checksum_ptr.assume_init() };
        let checksum = unsafe { slice::from_raw_parts(checksum_ptr.contents, checksum_ptr.length as usize) };
        Ok(checksum)
    }

    pub fn create_mic_token_header(usage: Krb5KeyUsage, seq_num: i32) -> Vec<u8> {
        let tok_id = TOK_MIC_MSG.to_be_bytes();
        let flags = Krb5Context::get_token_flags(usage).to_be_bytes();
        let filler = b"\xFF\xFF\xFF\xFF\xFF";
        let seq_num = (seq_num as i64).to_be_bytes();

        [&tok_id, flags.as_slice(), filler, &seq_num].concat()
    }

    fn get_token_flags(usage: Krb5KeyUsage) -> Krb5TokenFlag {
        match usage {
            Krb5KeyUsage::AcceptorSign => Krb5TokenFlag::SentByAcceptor | Krb5TokenFlag::AcceptorSubkey,
            Krb5KeyUsage::InitiatorSign => Krb5TokenFlag::AcceptorSubkey,
            Krb5KeyUsage::AcceptorSeal => Krb5TokenFlag::Sealed | Krb5TokenFlag::SentByAcceptor | Krb5TokenFlag::AcceptorSubkey,
            Krb5KeyUsage::InitiatorSeal => Krb5TokenFlag::Sealed | Krb5TokenFlag::AcceptorSubkey,
        }
    }

    // TODO: this produces invalid UTF-8?
    /*
    pub fn expand_hostname(&self, hostname: &str) -> Result<String, Krb5Error> {
        let hostname_c = string_to_c_string(hostname)?;
        let mut cstr_ptr: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_expand_hostname(self.context, hostname_c, cstr_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self, code)?;
        let cstr_ptr = unsafe { cstr_ptr.assume_init() };

        let result = c_string_to_string(cstr_ptr);
        unsafe { krb5_free_string(self.context, cstr_ptr) };

        result
    }
    */

    pub(crate) fn error_code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };

        match c_string_to_string(message) {
            Ok(string) => {
                unsafe { krb5_free_error_message(self.context, message) };
                string
            },
            Err(error) => error.to_string(),
        }
    }
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context for de-initialization.");

        unsafe { krb5_free_context(self.context) };
    }
}

#[derive(Debug)]
pub struct Krb5AuthContext<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) auth_context: krb5_auth_context,
}

impl<'a> Krb5AuthContext<'a> {
    pub fn new(context: &'a Krb5Context, session_key: Option<&Krb5Keyblock>) -> Result<Krb5AuthContext<'a>, Krb5Error> {
        let mut auth_context_ptr: MaybeUninit<krb5_auth_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_auth_con_init(context.context, auth_context_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(context, code)?;

        let auth_context = Krb5AuthContext {
            context: &context,
            auth_context: unsafe { auth_context_ptr.assume_init() },
        };

        match session_key {
            Some(keyblock) => {
                auth_context.set_userkey(keyblock)?;
            },
            None => {},
        }

        Ok(auth_context)
    }

    pub fn set_userkey(&self, keyblock: &Krb5Keyblock) -> Result<(), Krb5Error> {
        let mut keyblock = keyblock.to_owned();
        let code: krb5_error_code =
            unsafe { krb5_auth_con_setuseruserkey(self.context.context, self.auth_context, keyblock.to_c()) };
        krb5_error_code_escape_hatch(self.context, code)?;

        Ok(())
    }

    pub fn get_local_seq_num(&self) -> Result<i32, Krb5Error> {
        let mut seq_num: i32 = 0;
        let code = unsafe { krb5_auth_con_getlocalseqnumber(self.context.context, self.auth_context, &mut seq_num) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(seq_num)
    }

    pub fn get_remote_seq_num(&self) -> Result<i32, Krb5Error> {
        let mut seq_num: i32 = 0;
        let code = unsafe { krb5_auth_con_getremoteseqnumber(self.context.context, self.auth_context, &mut seq_num) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(seq_num)
    }

    pub fn set_flags(&self, flags: i32) -> Result<(), Krb5Error> {
        let code = unsafe { krb5_auth_con_setflags(self.context.context, self.auth_context, flags) };
        krb5_error_code_escape_hatch(self.context, code)?;

        Ok(())
    }

    pub fn get_authenticator(&self) -> Result<Krb5Authenticator, Krb5Error> {
        let mut authenticator_ptr: MaybeUninit<*mut krb5_authenticator> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_auth_con_getauthenticator(self.context.context, self.auth_context, authenticator_ptr.as_mut_ptr())
        };
        krb5_error_code_escape_hatch(self.context, code)?;

        let authenticator = Krb5Authenticator {
            context: self.context,
            authenticator: unsafe { authenticator_ptr.assume_init() },
        };

        Ok(authenticator)
    }

    pub fn get_sendsubkey(&self) -> Result<Krb5Keyblock, Krb5Error> {
        let mut keyblock_ptr: MaybeUninit<*mut krb5_keyblock> = MaybeUninit::zeroed();
        let code =
            unsafe { krb5_auth_con_getsendsubkey(self.context.context, self.auth_context, keyblock_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let keyblock = unsafe { Krb5Keyblock::from_c(&(*keyblock_ptr.assume_init())) };

        Ok(keyblock)
    }
}

impl<'a> Drop for Krb5AuthContext<'a> {
    fn drop(&mut self) {
        unsafe { krb5_auth_con_free(self.context.context, self.auth_context) };
    }
}

pub struct Krb5Authenticator<'a> {
    context: &'a Krb5Context,
    authenticator: *mut krb5_authenticator,
}

impl<'a> Drop for Krb5Authenticator<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_authenticator(self.context.context, self.authenticator);
        }
    }
}

impl<'a> Krb5Authenticator<'a> {}
#[derive(Debug)]
pub struct Krb5Ticket<'a> {
    context: &'a Krb5Context,
    ticket: *mut krb5_ticket,
}

impl<'a> Drop for Krb5Ticket<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_ticket(self.context.context, self.ticket);
        }
    }
}

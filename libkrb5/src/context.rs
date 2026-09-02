use bitflags::bitflags;
use core::slice;
use nom::error::ErrorKind;
use nom::number::complete::{be_u16, be_u64, be_u8, le_u32};
use nom::{bytes::streaming::take, sequence::tuple};
use std::cell::RefCell;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::iter;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::Mutex;

use lazy_static::lazy_static;
use libkrb5_sys::*;

use crate::ccache::Krb5CCache;
use crate::credential::{Krb5Creds, Krb5Keyblock};
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::profile::Krb5Profile;
use crate::strconv::{c_string_to_string, string_to_c_string};

pub use libkrb5_sys::{
    KRB5_AUTH_CONTEXT_DO_SEQUENCE,
    KRB5_AUTH_CONTEXT_DO_TIME,
    KRB5_AUTH_CONTEXT_PERMIT_ALL,
    KRB5_AUTH_CONTEXT_RET_SEQUENCE,
    KRB5_AUTH_CONTEXT_RET_TIME,
    KRB5_AUTH_CONTEXT_USE_SUBKEY,
    KRB5_PRINCIPAL_PARSE_ENTERPRISE,
    KRB5_PRINCIPAL_PARSE_IGNORE_REALM,
    KRB5_PRINCIPAL_PARSE_NO_DEF_REALM,
    KRB5_PRINCIPAL_PARSE_NO_REALM,
    KRB5_PRINCIPAL_PARSE_REQUIRE_REALM,
};

lazy_static! {
    static ref CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());
}

const TOK_MIC_MSG: &[u8] = b"\x04\x04";
const TOK_WRAP_MSG: &[u8] = b"\x05\x04";
const GSS_CHECKSUM_TYPE: i32 = 0x8003;

struct HexDump<'a> {
    data: &'a [u8],
}

impl<'a> HexDump<'a> {
    fn from(data: &'a [u8]) -> HexDump<'a> {
        HexDump { data }
    }
}

impl<'a> Debug for HexDump<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        let mut sep = "";
        for i in self.data.iter() {
            write!(f, "{}", sep)?;
            write!(f, "{:#04X}", i)?;
            sep = " ";
        }
        Ok(())
    }
}

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

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Krb5AuthContextOptions {
    Deleg = 1,
    Mutual = 2,
    Replay = 4,
    Sequence = 8,
    Conf = 16,
    Integ = 32,
}

#[derive(Clone, Debug)]
pub struct Krb5Context {
    // NOTE: `trace_cb` must be declared before `context` so that on drop the
    // trace callback is unregistered *before* `krb5_free_context` runs.
    // Rust drops struct fields in declaration order.
    pub(crate) trace_cb: Rc<RefCell<Option<TraceCallbackHolder>>>,
    pub(crate) context: Rc<krb5_context>,
}

/// Owned storage for a registered trace callback.
///
/// The `Box<dyn Fn>` must outlive any libkrb5 call that could fire the
/// callback. Dropping this holder unregisters the callback from the context
/// first, then frees the boxed closure.
pub struct TraceCallbackHolder {
    context: krb5_context,
    // The closure is kept alive here; libkrb5 stores a raw pointer to it.
    _closure: Box<Box<dyn Fn(&str) + Send + Sync>>,
}

impl Debug for TraceCallbackHolder {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.debug_struct("TraceCallbackHolder").finish()
    }
}

impl Drop for TraceCallbackHolder {
    fn drop(&mut self) {
        // SAFETY: `self.context` is still valid here because `Krb5Context`
        // declares `trace_cb` before `context`, so this drop runs while the
        // krb5_context is still allocated.
        unsafe {
            krb5_set_trace_callback(self.context, None, null_mut());
        }
    }
}

unsafe extern "C" fn trace_callback_trampoline(
    _context: krb5_context,
    info: *const krb5_trace_info,
    cb_data: *mut c_void,
) {
    // libkrb5 calls the callback with info == NULL when the callback is being
    // unregistered; ignore that case.
    if info.is_null() || cb_data.is_null() {
        return;
    }

    let msg_ptr = (*info).message;
    if msg_ptr.is_null() {
        return;
    }

    // Reborrow the boxed closure without taking ownership.
    let closure: &Box<dyn Fn(&str) + Send + Sync> =
        &*(cb_data as *const Box<dyn Fn(&str) + Send + Sync>);

    let msg = CStr::from_ptr(msg_ptr).to_string_lossy();

    // Never let a panic unwind across the FFI boundary into libkrb5.
    let _ = catch_unwind(AssertUnwindSafe(|| closure(&msg)));
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        if Rc::strong_count(&self.context) == 1 {
            let _guard = CONTEXT_INIT_LOCK
                .lock()
                .expect("Failed to lock context for de-initialization.");

            unsafe { krb5_free_context(self.get_context()) };
        }
    }
}

impl Krb5Context {
    pub fn init() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            trace_cb: Rc::new(RefCell::new(None)),
            context: unsafe { Rc::new(context_ptr.assume_init()) },
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
            trace_cb: Rc::new(RefCell::new(None)),
            context: unsafe { Rc::new(context_ptr.assume_init()) },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    /// Initialise a Kerberos context using a caller-supplied profile
    /// instead of reading `/etc/krb5.conf`.
    ///
    /// The profile is borrowed for the duration of the call: MIT krb5
    /// duplicates it internally (via `krb5int_dup_profile`), so the
    /// caller retains ownership and the [`Krb5Profile`] may safely be
    /// dropped or reused afterwards.
    pub fn init_with_profile(profile: &Krb5Profile) -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        // SAFETY: profile.as_ptr() is a valid profile_t; context_ptr is a
        // valid out pointer.
        let code: krb5_error_code = unsafe {
            krb5_init_context_profile(profile.as_ptr(), 0, context_ptr.as_mut_ptr())
        };

        let context = Krb5Context {
            trace_cb: Rc::new(RefCell::new(None)),
            context: unsafe { Rc::new(context_ptr.assume_init()) },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    //returns the reference counted krb5_context pointer
    pub fn get_context(&self) -> krb5_context {
        *Rc::as_ref(&self.context)
    }

    /// Register a callback that receives every libkrb5 trace line.
    ///
    /// Equivalent to setting `KRB5_TRACE=<file>` at process start, but the
    /// caller decides what to do with each line (typically forward it to an
    /// application log). Any previously registered callback is replaced.
    ///
    /// The callback runs synchronously on whichever thread issued the
    /// underlying krb5 call, and must not itself invoke krb5 API on the same
    /// context (reentrancy is not supported by libkrb5).
    pub fn set_trace_callback<F>(&self, callback: F) -> Result<(), Krb5Error>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        // Double-box: the outer Box gives us a stable heap address to hand to
        // libkrb5 as `cb_data`; the inner Box<dyn Fn> is the type-erased
        // closure.
        let boxed: Box<Box<dyn Fn(&str) + Send + Sync>> = Box::new(Box::new(callback));
        let cb_data = &*boxed as *const Box<dyn Fn(&str) + Send + Sync> as *mut c_void;

        // Drop any previously registered callback first (its Drop unregisters
        // at the libkrb5 level), then install the new one.
        *self.trace_cb.borrow_mut() = None;

        let code = unsafe {
            krb5_set_trace_callback(
                self.get_context(),
                Some(trace_callback_trampoline),
                cb_data,
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        *self.trace_cb.borrow_mut() = Some(TraceCallbackHolder {
            context: self.get_context(),
            _closure: boxed,
        });

        Ok(())
    }

    /// Unregister any trace callback previously installed with
    /// [`set_trace_callback`].
    pub fn clear_trace_callback(&self) {
        // Dropping the holder unregisters the callback via libkrb5.
        *self.trace_cb.borrow_mut() = None;
    }

    pub fn build_principal<'a>(&'a self, realm: &'a str, args: &'a [String]) -> Result<Krb5Principal, Krb5Error> {
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
            0 => unsafe {
                krb5_build_principal(self.get_context(), principal_ptr.as_mut_ptr(), realml, crealm.as_ptr())
            },
            1 => unsafe {
                krb5_build_principal(
                    self.get_context(),
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm.as_ptr(),
                    varargs[0].as_ptr(),
                    std::ptr::null::<*const c_char>(),
                )
            },
            2 => unsafe {
                krb5_build_principal(
                    self.get_context(),
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
                    self.get_context(),
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
                    self.get_context(),
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
            context: self.clone(),
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    pub fn parse_principal(&self, name: &str) -> Result<Krb5Principal, Krb5Error> {
        let c_name = string_to_c_string(name)?;
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        let code = unsafe { krb5_parse_name(self.get_context(), c_name.as_ptr(), principal_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let principal = Krb5Principal {
            context: self.clone(),
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    pub fn parse_principal_flags(&self, name: &str, flags: i32) -> Result<Krb5Principal, Krb5Error> {
        let c_name = string_to_c_string(name)?;
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        let code = unsafe {
            krb5_parse_name_flags(self.get_context(), c_name.as_ptr(), flags, principal_ptr.as_mut_ptr())
        };
        krb5_error_code_escape_hatch(self, code)?;

        let principal = Krb5Principal {
            context: self.clone(),
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    pub fn get_default_realm(&self) -> Result<Option<String>, Krb5Error> {
        let mut realm: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_get_default_realm(self.get_context(), realm.as_mut_ptr()) };

        if code == KRB5_CONFIG_NODEFREALM {
            return Ok(None);
        }

        krb5_error_code_escape_hatch(self, code)?;

        let realm = unsafe { realm.assume_init() };

        let string = c_string_to_string(realm)?;
        unsafe { krb5_free_default_realm(self.get_context(), realm) };

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

        let code: krb5_error_code =
            unsafe { krb5_get_host_realm(self.get_context(), c_host_ptr, c_realms.as_mut_ptr()) };
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

        unsafe { krb5_free_host_realm(self.get_context(), c_realms) };

        Ok(realms)
    }

    pub fn req_tgs(
        &self,
        mut in_creds: Krb5Creds,
        principal: &Krb5Principal,
        second_ticket: &Vec<u8>,
    ) -> Result<Krb5Creds, Krb5Error> {
        let tgs_options: krb5_flags = (KRB5_GC_FORWARDABLE | KRB5_GC_USER_USER) as i32;

        let second_ticket_buffer = unsafe {
            let buffer = std::alloc::alloc_zeroed(std::alloc::Layout::for_value(second_ticket.as_slice()));
            std::ptr::copy_nonoverlapping(second_ticket.as_ptr(), buffer, second_ticket.len());
            buffer
        };

        let data = krb5_data {
            magic: 0,
            data: second_ticket_buffer as *mut i8,
            length: second_ticket.len() as u32,
        };

        in_creds.creds.second_ticket = data;

        let mut ccache: Krb5CCache = Krb5CCache::new_unique(&self, "MEMORY")?;
        {
            let principal: Krb5Principal = in_creds.get_client_principal()?;
            ccache.initialize(&principal)?;
        }
        ccache.store(&in_creds)?;

        in_creds.set_server_principal(principal)?;
        principal.data().set_type(KRB5_NT_SRV_INST as i32);

        let mut creds_ptr: MaybeUninit<*mut krb5_creds> = MaybeUninit::zeroed();
        let code: krb5_error_code = unsafe {
            krb5_get_credentials(
                self.get_context(),
                tgs_options,
                ccache.ccache,
                &mut in_creds.creds,
                creds_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let creds_ptr = unsafe { creds_ptr.assume_init() };
        let creds = Krb5Creds {
            context: self.clone(),
            creds: unsafe { *creds_ptr },
        };

        // At this point Krb5Creds gains ownership of the content, but not the whole struct, thus we
        // still have to free it.
        unsafe { libc::free(creds_ptr as *mut libc::c_void) };

        Ok(creds)
    }

    pub fn create_ap_req<'a>(
        &self,
        auth_context: &'a mut Krb5AuthContext,
        user_creds: &'a mut Krb5Creds,
    ) -> Result<Vec<u8>, Krb5Error> {
        let mut ap_req_ptr: MaybeUninit<krb5_data> = MaybeUninit::zeroed();
        let mut auth_ctx = auth_context.auth_context;
        let ap_req_options: krb5_flags = (AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_USE_SESSION_KEY) as i32;

        /* Assemble the authenticator checksum field, as per RFC 4121, section 4.1.1.
        We only use the Flags field to request service options from the server. */
        let code = unsafe {
            krb5_auth_con_set_req_cksumtype(self.get_context(), auth_context.auth_context, GSS_CHECKSUM_TYPE)
        };
        krb5_error_code_escape_hatch(self, code)?;

        auth_context.set_flags(KRB5_AUTH_CONTEXT_DO_SEQUENCE as i32 | KRB5_AUTH_CONTEXT_DO_TIME as i32)?;

        let checksum_flags = Krb5AuthContextOptions::Integ as i32
            | Krb5AuthContextOptions::Conf as i32
            | Krb5AuthContextOptions::Replay as i32
            | Krb5AuthContextOptions::Sequence as i32
            | Krb5AuthContextOptions::Mutual as i32;
        let binding_length: u32 = 16;
        let binding_info: Vec<u8> = iter::repeat(0).take(16).collect();
        let mut checksum_data: Vec<u8> = [
            &binding_length.to_le_bytes(),
            binding_info.as_slice(),
            &checksum_flags.to_le_bytes(),
        ]
        .concat();
        let mut in_data = krb5_data {
            magic: 0,
            data: checksum_data.as_mut_ptr() as *mut i8,
            length: checksum_data.len() as u32,
        };

        let code = unsafe {
            krb5_mk_req_extended(
                self.get_context(),
                &mut auth_ctx,
                ap_req_options,
                &mut in_data,
                &mut user_creds.creds,
                ap_req_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let mut ap_req_ptr = unsafe { ap_req_ptr.assume_init() };
        let ap_req = unsafe { slice::from_raw_parts(ap_req_ptr.data as *mut u8, ap_req_ptr.length as usize).to_vec() };
        unsafe { krb5_free_data_contents(self.get_context(), &mut ap_req_ptr) };

        Ok(ap_req)
    }

    pub fn verify_ap_rep<'a>(&self, auth_context: &'a mut Krb5AuthContext, ap_rep: &'a [u8]) -> Result<(), Krb5Error> {
        let mut ap_rep_ptr: MaybeUninit<*mut krb5_ap_rep_enc_part> = MaybeUninit::zeroed();
        let data = krb5_data {
            magic: 0,
            data: ap_rep.as_ptr() as *mut i8,
            length: ap_rep.len() as u32,
        };
        let code = unsafe {
            krb5_rd_rep(
                self.get_context(),
                auth_context.auth_context,
                &data,
                ap_rep_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;
        let ap_rep_ptr = unsafe { ap_rep_ptr.assume_init() };
        unsafe { krb5_free_ap_rep_enc_part(self.get_context(), ap_rep_ptr) };
        Ok(())
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
                self.get_context(),
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
            context: self.clone(),
            ticket: unsafe { ticket_ptr.assume_init() },
        };

        Ok((ap_req_options, ticket))
    }

    pub fn create_ap_rep<'a>(&self, auth_context: &'a Krb5AuthContext) -> Result<Vec<u8>, Krb5Error> {
        let mut ap_rep_ptr: MaybeUninit<krb5_data> = MaybeUninit::zeroed();
        let code = unsafe { krb5_mk_rep(self.get_context(), auth_context.auth_context, ap_rep_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let mut ap_rep_ptr = unsafe { ap_rep_ptr.assume_init() };
        let ap_rep = unsafe { slice::from_raw_parts(ap_rep_ptr.data as *mut u8, ap_rep_ptr.length as usize).to_vec() };
        unsafe { krb5_free_data_contents(self.get_context(), &mut ap_rep_ptr) };

        Ok(ap_rep)
    }

    /// Produce a GSS MIC token as per RFC 4121, section 4.2.4
    pub fn create_signature(
        &self,
        message_to_sign: &[u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
        local_seq_num: i32,
    ) -> Result<Vec<u8>, Krb5Error> {
        let header = Krb5Context::create_mic_token_header(usage, local_seq_num);
        let mut input_buf = [message_to_sign, header.as_slice()].concat();

        let checksum = self.create_checksum(input_buf.as_mut_slice(), key, usage)?;

        let mic_token = [header.as_slice(), &checksum].concat();
        Ok(mic_token)
    }

    /// Verify a GSS MIC token as per RFC 4121, section 4.2.4
    pub fn verify_signature(
        &self,
        message: &[u8],
        mic: &[u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
        seq_num: Option<i32>,
    ) -> Result<(), Krb5Error> {
        let received_header = &mic[0..16];
        let received_checksum = &mic[16..];

        Krb5Context::verify_mic_token_header(received_header, usage, seq_num)?;

        let mut input_buf = [message, received_header].concat();
        let expected_checksum = self.create_checksum(&mut input_buf, key, usage)?;

        if received_checksum != expected_checksum {
            return Err(Krb5Error::InvalidToken { message: format!("Kerberos mic token verification failed, invalid signature; expected_signature='{:?}', token_signature='{:?}'",
                HexDump::from(&expected_checksum), HexDump::from(&received_checksum))});
        }

        Ok(())
    }

    pub fn create_checksum(
        &self,
        input_buf: &mut [u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
    ) -> Result<Vec<u8>, Krb5Error> {
        let input_data = krb5_data {
            magic: 0,
            data: input_buf.as_mut_ptr() as *mut i8,
            length: input_buf.len() as u32,
        };

        let key = key.copy()?;
        let mut checksum_ptr: MaybeUninit<krb5_checksum> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_c_make_checksum(
                self.get_context(),
                0,
                key.keyblock,
                usage as i32,
                &input_data,
                checksum_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let mut checksum_ptr = unsafe { checksum_ptr.assume_init() };
        let checksum = unsafe { slice::from_raw_parts(checksum_ptr.contents, checksum_ptr.length as usize).to_vec() };
        unsafe { krb5_free_checksum_contents(self.get_context(), &mut checksum_ptr) };
        Ok(checksum)
    }

    /// Create a GSS MIC token header as per RFC 4121, section 4.2.6.1
    pub fn create_mic_token_header(usage: Krb5KeyUsage, seq_num: i32) -> Vec<u8> {
        let tok_id = TOK_MIC_MSG;
        let flags = Krb5Context::get_token_flags(usage);
        let filler = b"\xFF\xFF\xFF\xFF\xFF";
        let seq_num = (seq_num as i64).to_be_bytes();

        [&tok_id, flags.as_slice(), filler, &seq_num].concat()
    }

    fn verify_mic_token_header(
        token_header: &[u8],
        usage: Krb5KeyUsage,
        expected_seq_num: Option<i32>,
    ) -> Result<(), Krb5Error> {
        let mut parse_mic_token_header = tuple::<_, _, nom::error::Error<&[u8]>, _>((be_u16, be_u8, take(5u8), be_u64));
        let (_, (_, _, _, token_seq_num)) = parse_mic_token_header(token_header).or_else(|_| {
            Err(Krb5Error::InvalidToken {
                message: String::from("Kerberos mic token verification failed, short header;"),
            })
        })?;

        let expected_header =
            Krb5Context::create_mic_token_header(usage, expected_seq_num.unwrap_or(token_seq_num as i32));

        if expected_header != token_header {
            return Err(Krb5Error::InvalidToken { message: format!("Kerberos mic token verification failed, invalid header; expected_header='{:?}', token_header='{:?}'", HexDump::from(&expected_header), HexDump::from(&token_header)) });
        }

        Ok(())
    }

    /// Create a GSS wrap token header as per RFC 4121, section 4.2.6.2
    pub fn create_wrap_token_header(usage: Krb5KeyUsage, seq_num: i32, rrc: Option<u16>) -> Vec<u8> {
        let tok_id = TOK_WRAP_MSG;
        let flags = Krb5Context::get_token_flags(usage);
        let filler = b"\xFF";
        let ec: u16 = 0; /* Number of filler octets between the plain data and header. Since Microsoft's kerberos
                         implementation doesn't use a trailer buffer, this is always set to zero.*/
        let rrc: u16 = rrc.unwrap_or(0); /* rrc should be zero in the encrypted header */
        let seq_num = seq_num as i64;

        [
            &tok_id,
            flags.as_slice(),
            filler,
            &ec.to_be_bytes(),
            &rrc.to_be_bytes(),
            &seq_num.to_be_bytes(),
        ]
        .concat()
    }

    /// Calculate the Flags field for per-message tokens (mic or wrap)
    /// based on the key usage as per RFC 4121, section 4.2.2
    fn get_token_flags(usage: Krb5KeyUsage) -> [u8; 1] {
        let flags = match usage {
            Krb5KeyUsage::AcceptorSign => Krb5TokenFlag::SentByAcceptor | Krb5TokenFlag::AcceptorSubkey,
            Krb5KeyUsage::InitiatorSign => Krb5TokenFlag::AcceptorSubkey,
            Krb5KeyUsage::AcceptorSeal => {
                Krb5TokenFlag::Sealed | Krb5TokenFlag::SentByAcceptor | Krb5TokenFlag::AcceptorSubkey
            },
            Krb5KeyUsage::InitiatorSeal => Krb5TokenFlag::Sealed | Krb5TokenFlag::AcceptorSubkey,
        };
        flags.bits().to_be_bytes()
    }

    /// Encrypt plain_data and produce a GSS Wrap token as per RFC 4121 section 4.2.4
    pub fn encrypt(
        &self,
        plain_data: &[u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
        seq_num: i32,
    ) -> Result<Vec<u8>, Krb5Error> {
        let encrypt_header = Krb5Context::create_wrap_token_header(usage, seq_num, None);
        let mut plain_data = [plain_data, encrypt_header.as_slice()].concat();

        let mut trailer_length: u32 = 0;
        let code = unsafe {
            krb5_c_crypto_length(
                self.get_context(),
                (*key.keyblock).enctype,
                KRB5_CRYPTO_TYPE_TRAILER as i32,
                &mut trailer_length,
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let mut encrypted_length: usize = 0;
        let code = unsafe {
            krb5_c_encrypt_length(
                self.get_context(),
                (*key.keyblock).enctype,
                plain_data.len(),
                &mut encrypted_length,
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let input_buffer = krb5_data {
            magic: 0,
            data: plain_data.as_mut_ptr() as *mut i8,
            length: plain_data.len() as u32,
        };

        let mut encrypted_data_buffer = Vec::with_capacity(encrypted_length);
        let mut cipher_data = krb5_enc_data {
            magic: 0,
            kvno: 0,
            enctype: unsafe { (*key.keyblock).enctype },
            ciphertext: krb5_data {
                magic: 0,
                data: encrypted_data_buffer.as_mut_ptr() as *mut i8,
                length: encrypted_length as u32,
            },
        };

        let keyblock = key.copy()?;
        let code = unsafe {
            krb5_c_encrypt(
                self.get_context(),
                keyblock.keyblock,
                usage as i32,
                null(),
                &input_buffer,
                &mut cipher_data,
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let encrypted_data = unsafe {
            slice::from_raw_parts(
                cipher_data.ciphertext.data as *const u8,
                cipher_data.ciphertext.length as usize,
            )
        };

        /* The encrypted data is shifted to right by rrc octets, see RFC 4121, section 4.2.5 */
        let rrc = 16 + trailer_length as u16;
        let rotated_data = Krb5Context::rotate_right(encrypted_data, rrc);

        let mut encrypted_token = Krb5Context::create_wrap_token_header(usage, seq_num, Some(rrc));
        encrypted_token.extend_from_slice(rotated_data.as_slice());

        Ok(encrypted_token)
    }

    /// Decrypt and validate a GSS Wrap token as per RFC 4121 section 4.2.4
    pub fn decrypt(
        &self,
        encoded_data: &[u8],
        key: &Krb5Keyblock,
        usage: Krb5KeyUsage,
        remote_seq_num: Option<i32>,
    ) -> Result<Vec<u8>, Krb5Error> {
        let (mut header, mut cipher_text) = Krb5Context::parse_wrap_token(encoded_data, usage, remote_seq_num)?;

        let cipher_data = krb5_enc_data {
            magic: 0,
            kvno: 0,
            enctype: unsafe { (*key.keyblock).enctype },
            ciphertext: krb5_data {
                magic: 0,
                data: cipher_text.as_mut_ptr() as *mut i8,
                length: cipher_text.len() as u32,
            },
        };

        let mut plain_text = Vec::<u8>::with_capacity(cipher_text.len());
        let mut plain_data = krb5_data {
            magic: 0,
            data: plain_text.as_mut_ptr() as *mut i8,
            length: plain_text.capacity() as u32,
        };

        let key = key.copy()?;
        let code = unsafe {
            krb5_c_decrypt(
                self.get_context(),
                key.keyblock,
                usage as i32,
                null(),
                &cipher_data,
                &mut plain_data,
            )
        };
        krb5_error_code_escape_hatch(self, code)?;

        let plain_with_header =
            unsafe { slice::from_raw_parts_mut(plain_data.data as *mut u8, plain_data.length as usize) };

        let header_pos = plain_with_header.len() - 16;
        let plain = plain_with_header[0..header_pos].to_vec();
        let decrypted_header = &mut plain_with_header[header_pos..];

        /* As per RFC 4121, section 4.2.4, the rrc field is set to 0 in the encrypted header. After this,
         * it should be the same as the clear text header */
        header[6..8].copy_from_slice(&0_u16.to_be_bytes());
        if decrypted_header != header {
            return Err(Krb5Error::InvalidToken {message: format!("Kerberos token decryption failed, cleartext header modified; cleartext_header='{:?}', decrypted_header='{:?}'", HexDump::from(&header), HexDump::from(&decrypted_header))});
        }

        Ok(plain)
    }

    /// Parse the GSS Wrap token into clear text header and cipher text parts.
    fn parse_wrap_token(
        encoded_data: &[u8],
        usage: Krb5KeyUsage,
        seq_num: Option<i32>,
    ) -> Result<(Vec<u8>, Vec<u8>), Krb5Error> {
        let (header, cipher_text) = (encoded_data[..16].to_vec(), &encoded_data[16..]);

        let rrc = Krb5Context::parse_and_verify_wrap_token_header(header.as_slice(), usage, seq_num)?;
        /* The data is shifted to the left by rrc octets. See RFC 4121, section 2.4.5 */
        let cipher_text = Krb5Context::rotate_left(cipher_text, rrc);

        Ok((header, cipher_text))
    }

    fn parse_and_verify_wrap_token_header(
        token_header: &[u8],
        usage: Krb5KeyUsage,
        expected_seq_num: Option<i32>,
    ) -> Result<u16, Krb5Error> {
        let mut parse_wrap_token_header =
            tuple::<_, _, (&[u8], ErrorKind), _>((be_u16, be_u8, take(1u8), be_u16, be_u16, be_u64));
        let (_, (_, _, _, _, rrc, token_seq_num)) = parse_wrap_token_header(token_header).or_else(|_| {
            Err(Krb5Error::InvalidToken {
                message: String::from("Kerberos token decryption failed, short header"),
            })
        })?;

        let expected_header =
            Krb5Context::create_wrap_token_header(usage, expected_seq_num.unwrap_or(token_seq_num as i32), Some(rrc));

        if expected_header != token_header {
            return Err(Krb5Error::InvalidToken {
                message: format!(
                    "Kerberos token decryption failed, invalid header; expected_header='{:?}', token_header='{:?}'",
                    HexDump::from(&expected_header),
                    HexDump::from(&token_header)
                ),
            });
        }

        Ok(rrc)
    }

    fn rotate_left(cipher_text: &[u8], count: u16) -> Vec<u8> {
        let count = count as usize;
        [&cipher_text[count..], &cipher_text[0..count]].concat()
    }
    fn rotate_right(cipher_text: &[u8], count: u16) -> Vec<u8> {
        let rotation_start = cipher_text.len() - count as usize;
        [&cipher_text[rotation_start..], &cipher_text[0..rotation_start]].concat()
    }

    pub fn parse_error_message(&self, message: &[u8]) -> Result<(u32, String), Krb5Error> {
        let mut message = message.to_vec();
        let mut error_ptr: MaybeUninit<*mut krb5_error> = MaybeUninit::zeroed();

        let message_buffer = krb5_data {
            magic: 0,
            data: message.as_mut_ptr() as *mut i8,
            length: message.len() as u32,
        };
        let code = unsafe { krb5_rd_error(self.get_context(), &message_buffer, error_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(self, code)?;

        let error_ptr = unsafe { error_ptr.assume_init() };
        let error = unsafe { *error_ptr };
        let mut error_text = String::from("");

        if !error.text.data.is_null() {
            let text = unsafe { CStr::from_ptr(error.text.data) };
            error_text = match text.to_str() {
                Err(_) => {
                    format!(
                        "Invalid error message received; raw_error_text:'{:?}'",
                        HexDump::from(text.to_bytes_with_nul())
                    )
                },
                Ok(valid_error_text) => valid_error_text.to_string(),
            };
        }

        unsafe { krb5_free_error(self.get_context(), error_ptr) };

        Ok((error.error, error_text))
    }

    // TODO: this produces invalid UTF-8?
    /*
    pub fn expand_hostname(&self, hostname: &str) -> Result<String, Krb5Error> {
        let hostname_c = string_to_c_string(hostname)?;
        let mut cstr_ptr: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_expand_hostname(self.get_context(), hostname_c, cstr_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self, code)?;
        let cstr_ptr = unsafe { cstr_ptr.assume_init() };

        let result = c_string_to_string(cstr_ptr);
        unsafe { krb5_free_string(self.get_context(), cstr_ptr) };

        result
    }
    */

    pub(crate) fn error_code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.get_context(), code) };

        match c_string_to_string(message) {
            Ok(string) => {
                unsafe { krb5_free_error_message(self.get_context(), message) };
                string
            },
            Err(error) => error.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Krb5AuthContext {
    pub(crate) context: Krb5Context,
    pub(crate) auth_context: krb5_auth_context,
}

impl Krb5AuthContext {
    pub fn new(context: &Krb5Context, session_key: Option<&Krb5Keyblock>) -> Result<Krb5AuthContext, Krb5Error> {
        let mut auth_context_ptr: MaybeUninit<krb5_auth_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_auth_con_init(context.get_context(), auth_context_ptr.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&context, code)?;

        let auth_context = Krb5AuthContext {
            context: context.clone(),
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
        let key = keyblock.copy()?;
        let code: krb5_error_code =
            unsafe { krb5_auth_con_setuseruserkey(self.context.get_context(), self.auth_context, key.keyblock) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(())
    }

    pub fn get_local_seq_num(&self) -> Result<i32, Krb5Error> {
        let mut seq_num: i32 = 0;
        let code =
            unsafe { krb5_auth_con_getlocalseqnumber(self.context.get_context(), self.auth_context, &mut seq_num) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(seq_num)
    }

    pub fn get_remote_seq_num(&self) -> Result<i32, Krb5Error> {
        let mut seq_num: i32 = 0;
        let code =
            unsafe { krb5_auth_con_getremoteseqnumber(self.context.get_context(), self.auth_context, &mut seq_num) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(seq_num)
    }

    pub fn set_flags(&self, flags: i32) -> Result<(), Krb5Error> {
        let code = unsafe { krb5_auth_con_setflags(self.context.get_context(), self.auth_context, flags) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        Ok(())
    }

    pub fn get_authenticator(&self) -> Result<Krb5Authenticator, Krb5Error> {
        let mut authenticator_ptr: MaybeUninit<*mut krb5_authenticator> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_auth_con_getauthenticator(
                self.context.get_context(),
                self.auth_context,
                authenticator_ptr.as_mut_ptr(),
            )
        };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let authenticator = Krb5Authenticator {
            context: self.context.clone(),
            authenticator: unsafe { authenticator_ptr.assume_init() },
        };

        Ok(authenticator)
    }

    pub fn get_sendsubkey(&self) -> Result<Krb5Keyblock, Krb5Error> {
        let mut keyblock_ptr: MaybeUninit<*mut krb5_keyblock> = MaybeUninit::zeroed();
        let code = unsafe {
            krb5_auth_con_getsendsubkey(self.context.get_context(), self.auth_context, keyblock_ptr.as_mut_ptr())
        };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let keyblock_ptr = unsafe { keyblock_ptr.assume_init() };
        if keyblock_ptr.is_null() {
            return Err(Krb5Error::LibraryError {
                message: String::from("get_sendsubkey failed, auth context doesn't contain a subkey;"),
            });
        }

        let key = Krb5Keyblock {
            context: self.context.clone(),
            keyblock: keyblock_ptr,
        };

        Ok(key)
    }

    pub fn seq_num_required(&self) -> Result<bool, Krb5Error> {
        let flags = self.get_authenticator()?.get_flags()?;
        Ok((flags & Krb5AuthContextOptions::Sequence as u32) != 0)
    }
}

impl Drop for Krb5AuthContext {
    fn drop(&mut self) {
        unsafe { krb5_auth_con_free(self.context.get_context(), self.auth_context) };
    }
}

pub struct Krb5Authenticator {
    context: Krb5Context,
    authenticator: *mut krb5_authenticator,
}

impl Drop for Krb5Authenticator {
    fn drop(&mut self) {
        unsafe {
            krb5_free_authenticator(self.context.get_context(), self.authenticator);
        }
    }
}

impl Krb5Authenticator {
    pub fn get_client_principal(&self) -> Result<Krb5Principal, Krb5Error> {
        let principal = unsafe { (*self.authenticator).client };
        let mut out_princ: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
        let code = unsafe { krb5_copy_principal(self.context.get_context(), principal, out_princ.as_mut_ptr()) };
        krb5_error_code_escape_hatch(&self.context, code)?;

        let client_princ = Krb5Principal {
            context: self.context.clone(),
            principal: unsafe { out_princ.assume_init() },
        };

        Ok(client_princ)
    }

    pub fn get_flags(&self) -> Result<u32, Krb5Error> {
        let checksum = unsafe {
            let checksum_c = *(*self.authenticator).checksum;
            slice::from_raw_parts(checksum_c.contents, checksum_c.length as usize)
        };

        let mut parse_checksum = tuple::<_, _, (&[u8], nom::error::ErrorKind), _>((take(20u8), le_u32));
        let (_, (_, flags)) = parse_checksum(checksum).or_else(|_| {
            Err(Krb5Error::LibraryError {
                message: String::from("Can't fetch authenticator flags, checksum field is short"),
            })
        })?;

        Ok(flags)
    }
}

#[derive(Debug)]
pub struct Krb5Ticket {
    context: Krb5Context,
    ticket: *mut krb5_ticket,
}

impl Drop for Krb5Ticket {
    fn drop(&mut self) {
        unsafe {
            krb5_free_ticket(self.context.get_context(), self.ticket);
        }
    }
}

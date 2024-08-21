mod ccache;
pub use ccache::Krb5CCache;

mod cccol;
pub use cccol::Krb5CCCol;

mod context;
pub use context::{
    Krb5AuthContext, Krb5Context, Krb5KeyUsage, KRB5_AUTH_CONTEXT_DO_SEQUENCE, KRB5_AUTH_CONTEXT_DO_TIME,
    KRB5_AUTH_CONTEXT_PERMIT_ALL, KRB5_AUTH_CONTEXT_RET_SEQUENCE, KRB5_AUTH_CONTEXT_RET_TIME,
    KRB5_AUTH_CONTEXT_USE_SUBKEY,
};

mod credential;
pub use credential::{Krb5Creds, Krb5Keyblock, Krb5Keytab};

mod error;
pub use error::Krb5Error;

mod principal;
pub use principal::{Krb5Principal, Krb5PrincipalData};

mod strconv;

#[allow(dead_code)]
static C_FALSE: u32 = 0;
#[allow(dead_code)]
static C_TRUE: u32 = 1;

#[cfg(test)]
mod tests;

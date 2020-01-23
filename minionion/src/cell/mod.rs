// We support link protocol version 4 only
const CIRCID_LEN_NEW: usize = 4;
// Only used in initial handshake
const CIRCID_LEN_LEGACY: usize = 2;

mod auth_challenge;
mod certs;
mod fixed_cell;
mod net_info;
mod variable_cell;
pub(crate) mod versions;

pub(crate) use auth_challenge::AuthChallengeCell;
pub(crate) use certs::CertsCell;
pub(crate) use net_info::NetInfoCell;

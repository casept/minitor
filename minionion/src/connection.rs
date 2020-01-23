use mbedtls::rng::{CtrDrbg, OsEntropy};
use mbedtls::ssl::config::{AuthMode, Config, Endpoint, Preset, Transport, Version};
use mbedtls::ssl::context::{Context, Session};

use std::io::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;

use crate::cell;

// FIXME: Evaluate whether it should be public
pub struct TorConnection {}

impl TorConnection {
    /// Completes a v3 client -> relay handshake.
    /// Older versions are not supported.
    pub fn handshake(relay: SocketAddr) -> Result<TorConnection, Error> {
        let mut entropy = OsEntropy::new();
        let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng));
        // Security setup
        config.set_authmode(AuthMode::None);
        config.set_min_version(Version::Tls1_2).unwrap();
        //config.set_ciphersuites(&[
        //    CipherSuite::DheRsaWithAes256CbcSha as i32,
        //    CipherSuite::DheRsaWithAes256GcmSha384 as i32,
        //    CipherSuite::EcdhEcdsaWithAes256CbcSha as i32,
        //    0, // Don't ask me why this is needed, but it is checked by the wrapper whether the last element is 0
        //]); // Only support new relays

        let mut ctx = Context::new(&config).unwrap();

        // FIXME: Error handling
        // Connect to relay
        let mut stream = TcpStream::connect(relay)?;
        // Certificate validation is not needed (actual keys are fetched from dir authorities and negotiated later)
        let mut tls_stream = ctx.establish(&mut stream, None).unwrap();

        negotiate_version(&mut tls_stream);
        authenticate(&mut tls_stream);

        return Ok(TorConnection {});
    }
}

fn negotiate_version(sess: &mut Session) {
    println!("Sending VERSIONS cell");
    let our_version_cell = cell::versions::create_handshake_versions_cell();
    println!("{:?}", our_version_cell);
    sess.write_all(&our_version_cell.to_bytes()).unwrap();
    println!("Sent VERSIONS cell");
    println!("Reading VERSIONS cell");
    let their_version_cell = cell::versions::read_handshake_versions_cell(sess).unwrap();
    if !cell::versions::is_supported(&their_version_cell) {
        panic!("Relay does not support link protocol version 5");
    }
    println!("Link proto version 5 supported, continuing handshake");
    println!("{:?}", their_version_cell);
}

fn authenticate(sess: &mut Session) {
    println!("Reading CERTS cell");
    let certs_cell = cell::CertsCell::from_reader(sess).unwrap();
    println!("{:?}", certs_cell);
    // FIXME: VALIDATE CERTS!

    println!("Reading AUTH_CHALLENGE cell");
    let auth_challenge_cell = cell::AuthChallengeCell::from_reader(sess);
    println!("{:?}", auth_challenge_cell);

    println!("Reading NETINFO cell");
    let netinfo_cell = cell::NetInfoCell::from_reader(sess);
    println!("{:?}", netinfo_cell);
}

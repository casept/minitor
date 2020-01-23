use minionion::TorConnection;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
fn main() {
    let hardcoded_relay: SocketAddr =
        std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9001));
    TorConnection::handshake(hardcoded_relay).unwrap();
}

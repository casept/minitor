use super::variable_cell::{VariableCell, VariableCommand};

use std::io::{Cursor, Error, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

// Length of AUTH_CHALLENGE cell challenge
const CHALLENGE_LEN: usize = 32;

#[derive(Debug, Clone)]
enum AuthMethods {
    RsaSha256TlsSecret = 1,
    Ed25519Sha256Rfc5705 = 3,
}

impl AuthMethods {
    fn from_u16(b: u16) -> AuthMethods {
        match b {
            1 => AuthMethods::RsaSha256TlsSecret,
            3 => AuthMethods::Ed25519Sha256Rfc5705,
            _ => panic!("Unknown auth method: {}", b), // FIXME:
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthChallengeCell {
    challenge: [u8; CHALLENGE_LEN],
    methods: Vec<AuthMethods>,
}

impl AuthChallengeCell {
    pub(crate) fn from_reader(rdr: &mut dyn Read) -> Result<AuthChallengeCell, Error> {
        let cell = VariableCell::from_reader(rdr, false)?;
        if cell.command != VariableCommand::AuthChallenge {
            panic!("Expected AUTH_CHALLENGE cell type, got {:?}", cell.command);
        }
        let (challenge, methods) = AuthChallengeCell::parse(&cell);
        return Ok(AuthChallengeCell { challenge, methods });
    }

    // TODO: generate_challenge_response_cell()
    pub(crate) fn generate_challenge_response_cell(&self) {
        println!("{:?}", self);
    }

    fn parse(cell: &VariableCell) -> ([u8; CHALLENGE_LEN], Vec<AuthMethods>) {
        let mut c = Cursor::new(cell.clone().payload);

        let mut challenge: [u8; CHALLENGE_LEN] = [0x0; CHALLENGE_LEN];
        c.read_exact(&mut challenge).unwrap();

        let num_methods = c.read_u16::<NetworkEndian>().unwrap();

        let mut methods: Vec<AuthMethods> = vec![];
        for _i in 0..num_methods {
            methods.push(AuthMethods::from_u16(
                c.read_u16::<NetworkEndian>().unwrap(),
            ));
        }

        if methods.len() < 1 {
            panic!("Relay did not send any supported authentication methods"); // FIXME:
        }

        return (challenge, methods);
    }
}

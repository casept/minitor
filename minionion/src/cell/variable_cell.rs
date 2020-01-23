use std::convert::TryInto;
use std::io::{Cursor, Error, Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum VariableCommand {
    Versions = 7,
    VPadding = 128,
    Certs = 129,
    AuthChallenge = 130,
    Authenticate = 131,
    Authorize = 132,
}

impl VariableCommand {
    fn from_u8(b: u8) -> VariableCommand {
        match b {
            7 => VariableCommand::Versions,
            128 => VariableCommand::VPadding,
            129 => VariableCommand::Certs,
            130 => VariableCommand::AuthChallenge,
            131 => VariableCommand::Authenticate,
            132 => VariableCommand::Authorize,
            _ => panic!("Unknown variable command: {}", b),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VariableCell {
    pub(crate) circuit_id: Vec<u8>, // Either 2 or 4 bytes; length validated by constructor
    pub(crate) command: VariableCommand,
    pub(crate) length: u16, // Big endian!
    pub(crate) payload: Vec<u8>,
}

impl VariableCell {
    pub(crate) fn new(circuit_id: Vec<u8>, cmd: VariableCommand, payload: Vec<u8>) -> VariableCell {
        if circuit_id.len() != super::CIRCID_LEN_LEGACY && circuit_id.len() != super::CIRCID_LEN_NEW
        {
            panic!("Attempt to construct variable cell with invalid length circuit ID");
        }
        return VariableCell {
            circuit_id: circuit_id,
            command: cmd,
            length: payload.len() as u16,
            payload: payload,
        };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut vector: Vec<u8> = vec![];
        vector.extend(self.circuit_id.iter());
        vector.push(self.command.clone() as u8);
        vector.write_u16::<NetworkEndian>(self.length).unwrap();
        vector.extend(self.payload.iter());
        return vector;
    }
    pub(crate) fn from_reader(
        rdr: &mut dyn Read,
        use_legacy_circid_len: bool,
    ) -> Result<VariableCell, Error> {
        let mut circ_id: Vec<u8> = vec![];
        if use_legacy_circid_len {
            circ_id.resize(2, 0x0);
        } else {
            circ_id.resize(4, 0x0);
        }
        rdr.read_exact(&mut circ_id)?;

        let mut cmd_buf: [u8; 1] = [0; 1];
        rdr.read_exact(&mut cmd_buf)?;
        let cmd = VariableCommand::from_u8(cmd_buf[0]);
        let length = rdr.read_u16::<NetworkEndian>()?;
        let mut payload: Vec<u8> = vec![];
        payload.resize(length.try_into().unwrap(), 0x0);
        rdr.read_exact(&mut payload).unwrap();

        return Ok(VariableCell::new(circ_id, cmd, payload));
    }
}

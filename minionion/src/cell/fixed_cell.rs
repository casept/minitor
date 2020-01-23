use std::convert::TryInto;
use std::io::{Error, Read};

// Size of fixed-size cell payload
const PAYLOAD_LEN: usize = 509;
// Total length of fixed-size cell
const CELL_LEN: usize = 514; // For version 4
const CIRCID_LEN: usize = 4; // We support link protocol version 4 only

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FixedCommand {
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    CreateFast = 5,
    CreatedFast = 6,
    Netinfo = 8, // 8, not 7
    RelayEarly = 9,
    Create2 = 10,
    Created2 = 11,
    PaddingNegotiate = 12,
}

impl FixedCommand {
    fn from_u8(b: u8) -> FixedCommand {
        match b {
            0 => FixedCommand::Padding,
            1 => FixedCommand::Create,
            2 => FixedCommand::Created,
            3 => FixedCommand::Relay,
            4 => FixedCommand::Destroy,
            5 => FixedCommand::CreateFast,
            6 => FixedCommand::CreatedFast,
            8 => FixedCommand::Netinfo, // 8, not 7
            9 => FixedCommand::RelayEarly,
            10 => FixedCommand::Create2,
            11 => FixedCommand::Created2,
            12 => FixedCommand::PaddingNegotiate,
            _ => panic!("Invalid command!"), // FIXME: Error handling
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FixedCell {
    pub(crate) circuit_id: [u8; super::CIRCID_LEN_NEW],
    pub(crate) command: FixedCommand,
    pub(crate) payload: Vec<u8>,
}

impl FixedCell {
    fn new(
        payload: Vec<u8>,
        should_pad: bool,
        padding_byte: Option<u8>,
        cmd: FixedCommand,
        circ_id: [u8; CIRCID_LEN],
    ) -> FixedCell {
        if payload.len() > PAYLOAD_LEN {
            // FIXME:
            panic!("Payload too large!");
        }

        if should_pad && payload.len() < PAYLOAD_LEN {
            let padding_len = PAYLOAD_LEN - payload.len();

            let byte: u8;
            match padding_byte {
                Some(x) => byte = x,
                None => byte = 0x00,
            }

            let mut payload = payload.clone();
            for _i in 0..padding_len {
                payload.push(byte);
            }
        }

        return FixedCell {
            circuit_id: circ_id,
            command: cmd,
            payload: payload,
        };
    }

    pub(crate) fn from_bytes(buf: [u8; CELL_LEN]) -> FixedCell {
        let circ_id: [u8; CIRCID_LEN] = buf[0..CIRCID_LEN].try_into().unwrap();
        let cmd = FixedCommand::from_u8(buf[CIRCID_LEN]);
        let payload: Vec<u8> = buf[(CIRCID_LEN + 1)..PAYLOAD_LEN].to_vec();
        return FixedCell::new(payload, true, Some(0x0), cmd, circ_id);
    }

    pub(crate) fn from_reader(rdr: &mut dyn Read) -> Result<FixedCell, Error> {
        let mut buf: [u8; CELL_LEN] = [0x0; CELL_LEN];
        rdr.read_exact(&mut buf)?;
        return Ok(FixedCell::from_bytes(buf));
    }

    pub(crate) fn to_bytes(&self) -> [u8; CELL_LEN] {
        let mut vector: Vec<u8> = vec![];
        let mut buf: [u8; CELL_LEN] = [0x0; CELL_LEN];
        vector.extend(self.circuit_id.iter());
        vector.push(self.command.clone() as u8);
        vector.extend(self.payload.iter());
        for (i, item) in vector.iter().enumerate() {
            buf[i] = *item;
        }
        return buf;
    }
}

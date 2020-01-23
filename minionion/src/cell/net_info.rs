use super::fixed_cell::{FixedCell, FixedCommand};
use std::io::{Error, Read};

#[derive(Debug, Clone)]
pub(crate) struct NetInfoCell {
    cell: FixedCell,
}

impl NetInfoCell {
    pub(crate) fn from_reader(rdr: &mut dyn Read) -> Result<NetInfoCell, Error> {
        let cell = FixedCell::from_reader(rdr)?;
        if cell.command != FixedCommand::Netinfo {
            panic!("Expected NETINFO cell type, got {:?}", cell.command);
        }
        return Ok(NetInfoCell { cell });
    }
}

use super::variable_cell::{VariableCell, VariableCommand};
use std::io::{Error, Read};

/// Creates a VERSIONS cell with the versions we support.
/// Note that the handshake cell has special logic, as the CIRCID_LEN is 2 instead of 4.
pub(crate) fn create_handshake_versions_cell() -> VariableCell {
    return VariableCell::new(vec![0x0, 0x0], VariableCommand::Versions, vec![0x0, 0x5]);
}

/// Reads the initial VERSIONS cell from the Reader.
/// This requires special logic because of the use of CIRCID_LEN_LEGACY.
pub(crate) fn read_handshake_versions_cell(rdr: &mut dyn Read) -> Result<VariableCell, Error> {
    return VariableCell::from_reader(rdr, true);
}

/// Checks whether a particular VERSIONS cell contains a version we support.
pub(crate) fn is_supported(cell: &VariableCell) -> bool {
    return cell.payload.contains(&0x5); // FIXME: Proper parsing
}

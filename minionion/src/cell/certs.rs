use super::variable_cell::{VariableCell, VariableCommand};
use byteorder::{NetworkEndian, ReadBytesExt};
use mbedtls::x509::certificate::Certificate;
use std::io::{Cursor, Error, Read};
use std::convert::TryInto;

#[derive(Debug)]
pub(crate) struct CertsCell {
    certs: Vec<Cert>,
}

#[derive(Debug)]
enum CertType {
    LinkKeyRSA1024 = 1,
    RSA1024IdentitySelfSigned = 2,
    RSA1024AUTHENTICATECellLinkCertificate = 3,
    Ed25519SigningKey = 4,
    TLSLinkCertificate = 5,
    Ed25519AuthenticateCellKey = 6,
    Ed25519Identity = 7,
}

impl CertType {
    fn from_u8(b: u8) -> CertType {
        use CertType::*;
        match b {
            1 => LinkKeyRSA1024,
            2 => RSA1024IdentitySelfSigned,
            3 => RSA1024AUTHENTICATECellLinkCertificate,
            4 => Ed25519SigningKey,
            5 => TLSLinkCertificate,
            6 => Ed25519AuthenticateCellKey,
            7 => Ed25519Identity,
            _ => panic!("Unknown certificate type: {}", b), // FIXME: Do not crash
        }
    }
}

#[derive(Debug)]
enum CertExtType {
    SignedWithEd25519Key = 4,
    RSAEd25519Cross = 7,
}

impl CertExtType {
    fn from_u8(b: u8) -> CertExtType {
        match b {
            4 => CertExtType::SignedWithEd25519Key,
            7 => CertExtType::RSAEd25519Cross,
            _ => panic!("Unknown certificate data extension type: {}", b),
        }
    }
}

#[derive(Debug)]
struct CertExtension {
    ext_type: CertExtType,
    rsa_ed25519_cross: Option<RSAEd25519Cross>,
    ed25519_key_extension: Option<SignedWithEd25519KeyExtension>,
}
#[derive(Debug)]
struct SignedWithEd25519KeyExtension {
    affects_validation: bool,
    key: [u8; 32],
}

#[derive(Debug)]
struct RSAEd25519Cross {
    ed25519_key: [u8; 32],
    expiration_date: u32,
    signature: Vec<u8>,
}

#[derive(Debug)]
struct TorCustomFormatCert {
    cert_type: u8,
    expiration_date: u32,
    cert_key_type: CertType,
    certified_key: [u8; 32],
    extensions: Option<Vec<CertExtension>>,
    signature: Vec<u8>, // Actually always 64 bytes long, but Debug can't be autoderived on long arrays
}

impl TorCustomFormatCert {
    fn from_reader(rdr: &mut dyn Read) -> Result<TorCustomFormatCert, Error> {
        let mut ver_buf: [u8; 1] = [0x0];
        rdr.read_exact(&mut ver_buf)?;
        // FIXME: Don't panic
        if ver_buf[0] != 0x1 {
            panic!(
                "Invalid tor custom format certificate version: {}, expected 1",
                ver_buf[0]
            );
        }

        let mut cert_type_buf: [u8; 1] = [0x0];
        rdr.read_exact(&mut cert_type_buf)?;
        let cert_type = cert_type_buf[0];

        let mut expiration_date_buf: [u8; 4] = [0x0; 4];
        rdr.read_exact(&mut expiration_date_buf)?;
        let expiration_date = expiration_date_buf.as_ref().read_u32::<NetworkEndian>()?;

        let mut cert_key_type_buf: [u8; 1] = [0x0];
        rdr.read_exact(&mut cert_key_type_buf)?;
        let cert_key_type = CertType::from_u8(cert_key_type_buf[0]);

        let mut certified_key: [u8; 32] = [0x0; 32];
        rdr.read_exact(&mut certified_key)?;

        let mut num_extensions_buf: [u8; 1] = [0x0];
        rdr.read_exact(&mut num_extensions_buf)?;

        let mut extensions: Vec<CertExtension> = vec![];
        for _i in 0..num_extensions_buf[0] {
            let ext_length = rdr.read_u16::<NetworkEndian>()?;

            let mut ext_type_buf: [u8; 1] = [0x0; 1];
            rdr.read_exact(&mut ext_type_buf)?;
            let ext_type = CertExtType::from_u8(ext_type_buf[0]);

            let mut ext_flags_buf: [u8; 1] = [0x0; 1];
            rdr.read_exact(&mut ext_flags_buf)?;

            // Only the "affects validation" flag is currently defined
            let mut affects_validation = false;
            match ext_flags_buf[0] {
                0 => (),
                1 => affects_validation = true,
                _ => panic!("Unknown certificate extension flag: {}", ext_flags_buf[0]),
            }

            let mut ext_data: Vec<u8> = Vec::new();
            ext_data.resize(ext_length as usize, 0x0);
            rdr.read_exact(&mut ext_data)?;

            let ed25519_cross: Option<RSAEd25519Cross>;
            let signed_with_ed25519_key_extension: Option<SignedWithEd25519KeyExtension>;
            match ext_type {
                CertExtType::RSAEd25519Cross => {
                    parse_ed25519_cross(&mut &*ext_data);
                }
                CertExtType::SignedWithEd25519Key => {
                    parse_signed_with_ed25519_key(&mut &*ext_data);
                }
            }
            extensions.push(CertExtension { rsa_ed25519_cross: None, ext_type: ext_type, ed25519_key_extension: None });
        }

        let mut signature_buf: Vec<u8> = vec![];
        signature_buf.resize(64, 0x0);
        rdr.read_exact(&mut signature_buf)?;
        if extensions.len() > 0 {
            return Ok(TorCustomFormatCert {
                cert_type: cert_type,
                expiration_date: expiration_date,
                cert_key_type: cert_key_type,
                certified_key: certified_key,
                extensions: Some(extensions),
                signature: signature_buf,
            });
        } else {
            return Ok(TorCustomFormatCert {
                cert_type: cert_type,
                expiration_date: expiration_date,
                cert_key_type: cert_key_type,
                certified_key: certified_key,
                extensions: None,
                signature: signature_buf,
            });
        }
    }
}

#[derive(Debug)]
pub(crate) struct Cert {
    cert_type: CertType,
    tor_format_cert: Option<TorCustomFormatCert>,
    x509_cert: Option<Certificate>,
}

impl CertsCell {
    pub(crate) fn from_reader(rdr: &mut dyn Read) -> Result<CertsCell, Error> {
        let cell = VariableCell::from_reader(rdr, false)?;
        if cell.command != VariableCommand::Certs {
            panic!("Expected CERTS cell type, got {:?}", cell.command);
        }

        let mut c = Cursor::new(cell.payload);

        let mut num_certs_buf: [u8; 1] = [0x0];
        c.read_exact(&mut num_certs_buf)?;

        let mut certs: Vec<Cert> = vec![];
        for _i in 0..num_certs_buf[0] {
            let mut cert_type: [u8; 1] = [0x0];
            c.read_exact(&mut cert_type)?;
            let cert_type = CertType::from_u8(cert_type[0]);

            let cert_len = c.read_u16::<NetworkEndian>()?;
            let mut cert: Vec<u8> = vec![];
            cert.resize(cert_len as usize, 0x0);
            c.read_exact(&mut cert)?;

            let final_cert: Cert;
            println!("Cert type: {:?}", cert_type);
            match cert_type {
                // x509-based formats
                CertType::LinkKeyRSA1024
                | CertType::RSA1024IdentitySelfSigned
                | CertType::RSA1024AUTHENTICATECellLinkCertificate => {
                    final_cert = Cert {
                        cert_type,
                        x509_cert: Some(Certificate::from_der(&cert).unwrap()),
                        tor_format_cert: None,
                    }
                }

                _ => {
                    let mut c2 = Cursor::new(cert);
                    final_cert = Cert {
                        cert_type,
                        x509_cert: None,
                        tor_format_cert: Some(TorCustomFormatCert::from_reader(&mut c2).unwrap()),
                    }
                } // Tor's custom formats
            };
            certs.push(final_cert);
        }

        return Ok(CertsCell { certs });
    }
}

// FIXME: Implement
struct SignedWithEd25519Key {

}
fn parse_signed_with_ed25519_key(rdr: &mut dyn Read) -> SignedWithEd25519Key {
	return SignedWithEd25519Key{};
}

fn parse_ed25519_cross(rdr: &mut dyn Read) -> RSAEd25519Cross {
    let mut ed25519_key: [u8; 32] = [0x0; 32];
    rdr.read_exact(&mut ed25519_key);

    let mut expiration_date: [u8; 4] = [0x0; 4];
    rdr.read_exact(&mut expiration_date);

    let mut sig_len: [u8; 1] = [0x0;1];
    rdr.read_exact(&mut sig_len);

    let mut sig_buf: Vec<u8> = vec![];
    sig_buf.resize(sig_len[0].try_into().unwrap(), 0x0);
    rdr.read_exact(&mut sig_buf);

    return RSAEd25519Cross {
        ed25519_key: ed25519_key,
        expiration_date: expiration_date.as_ref().read_u32::<NetworkEndian>().unwrap(),
        signature: sig_buf,
    };
}

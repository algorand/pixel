//pub use bls_sigs_ref_rs::SerDes;
use clear_on_drop::ClearOnDrop;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use param::VALID_CIPHERSUITE;
use pixel_err::*;
use prng::PRNG;
use std::io::{Error, ErrorKind, Read, Result, Write};
use subkeys::SubSecretKey;
use PixelG1;
use PixelG2;
use ProofOfPossession;
use PublicKey;
use SecretKey;
use Signature;

/// Serialization support for pixel structures
pub trait PixelSerDes: Sized {
    /// Serialize a struct to a writer
    /// Whether a point is compressed or not is implicit for the structure:
    /// * public parameters: uncompressed
    /// * public keys: compressed
    /// * proof of possessions: compressed
    /// * secret keys: uncompressed
    /// * signatures: compressed
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;

    /// Deserialize a struct
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self>;
}

impl PixelSerDes for PixelG1 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        let t = self.into_affine();

        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = pairing::bls12_381::G2Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = pairing::bls12_381::G2Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a PixelG1 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G2Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        if (buf[0] & 0x80) == 0x80 {
            // first bit is 1 => compressed mode
            // convert the blob into a group element
            let mut g_buf = G2Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => compressed mode
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G2Uncompressed::size() - G2Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G2Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Should never reach here. Something is wrong",
            ))
        }
    }
}

impl PixelSerDes for PixelG2 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        let t = self.into_affine();
        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = pairing::bls12_381::G1Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = pairing::bls12_381::G1Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a PixelG2 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G1Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        if (buf[0] & 0x80) == 0x80 {
            // first bit is 1 => compressed mode
            // convert the buf into a group element
            let mut g_buf = G1Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => compressed mode
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G1Uncompressed::size() - G1Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G1Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Should never reach here. Something is wrong",
            ))
        }
    }
}

impl PixelSerDes for ProofOfPossession {
    /// Convert a pop into a blob:
    ///
    /// `|ciphersuite id| pop |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    /// Does not check if the pop is verified or not.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];
        self.get_pop().serialize(&mut buf, compressed)?;

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a PoP:
    ///
    /// bytes => `|ciphersuite id | pop |`
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into pop
        let pop = PixelG1::deserialize(reader)?;

        // finished
        Ok(ProofOfPossession::construct(constants[0], pop))
    }
}

impl PixelSerDes for Signature {
    /// Convert a signature into a blob:
    ///
    /// `|ciphersuite id| time | sigma1 | sigma2 |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    /// Does not check if the signature is verified or not.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // the time stamp cannot exceed 2^30
        let time = self.get_time();
        if time > (1 << 32) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_SERIAL));
        }

        // first byte is the ciphersuite id
        // the next 4 bytes stores the time stamp,

        let mut buf: Vec<u8> = vec![
            self.get_ciphersuite(),
            (time & 0xFF) as u8,
            (time >> 8 & 0xFF) as u8,
            (time >> 16 & 0xFF) as u8,
            (time >> 24 & 0xFF) as u8,
        ];

        // serialize sigma1
        self.get_sigma1().serialize(&mut buf, compressed)?;
        // serialize sigma2
        self.get_sigma2().serialize(&mut buf, compressed)?;
        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a signature:
    ///
    /// bytes => `|ciphersuite id | time | sigma1 | sigma2 |`
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_le_bytes(time);

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into sigma1
        let sigma1 = PixelG2::deserialize(reader)?;

        // read into sigma2
        let sigma2 = PixelG1::deserialize(reader)?;

        // finished
        Ok(Signature::construct(
            constants[0],
            u64::from(time),
            sigma1,
            sigma2,
        ))
    }
}

impl PixelSerDes for PublicKey {
    /// Convert pk into a blob:
    ///
    /// bytes => `|ciphersuite id| PixelG2 element |`
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];
        self.get_pk().serialize(&mut buf, compressed)?;

        // finished
        writer.write_all(&buf)?;
        Ok(())
    }
    /// Convert blob into a public key:
    ///
    /// `|ciphersuite id| PixelG2 element |` => bytes
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // read into pk
        let pk = PixelG2::deserialize(reader)?;

        // finished
        Ok(PublicKey::construct(constants[0], pk))
    }
}

impl PixelSerDes for SecretKey {
    /// Convert sk into a blob:
    ///
    /// `|ciphersuite id| number_of_ssk-s | seed | serial(first ssk) | serial(second ssk)| ...`,
    ///
    /// where ...
    /// * ciphersuite is 1 byte
    /// * number of ssk-s is 1 byte - there can not be more than const_d number of ssk-s
    /// * each ssk is
    ///
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
    ///
    /// Return an error if ssk serialization fails
    /// or invalid ciphersuite.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];

        // next byte is the number of ssk-s
        buf.push(self.get_ssk_number() as u8);

        // next 64 bytes is the seed for rng
        buf.extend(self.get_prng().get_seed().as_ref());

        // followed by serialization of the ssk-s
        for e in &self.get_ssk_vec() {
            e.serialize(&mut buf, compressed)?;
        }

        // finished
        writer.write_all(&buf)?;

        // clean the buf
        {
            let _clear = ClearOnDrop::new(&mut buf);
        }
        assert_eq!(buf, Vec::default());

        Ok(())
    }

    /// Convert a blob into a sk
    ///
    /// `|ciphersuite id| number_of_ssk-s | serial(first ssk) | serial(second ssk)| ...`,
    ///
    /// where ...
    /// * ciphersuite is 1 byte
    /// * number of ssk-s is 1 byte - there can not be more than const_d number of ssk-s
    /// * each ssk is
    ///
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
    ///
    /// Return an error if deserialization fails
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // constants stores id, the number of ssk-s, and the seed
        let mut constants: [u8; 2] = [0u8; 2];
        let mut rngseed: [u8; 64] = [0u8; 64];
        reader.read_exact(&mut constants)?;
        reader.read_exact(&mut rngseed)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // check the number of ssk is valid
        if constants[1] == 0 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_DESERIAL));
        }

        // deserialize the individual ssk
        let mut ssk_vec: Vec<SubSecretKey> = vec![];
        for _i in 0..constants[1] {
            ssk_vec.push(SubSecretKey::deserialize(reader)?);
        }

        // finished
        Ok(SecretKey::construct(
            constants[0],
            ssk_vec[0].get_time(),
            ssk_vec,
            PRNG::construct(rngseed),
        ))
    }
}

impl PixelSerDes for SubSecretKey {
    /// Conver ssk into a blob:
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
    /// Return an error if serialization fails or time stamp is greater than 2^32-1
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        let hvector = self.get_hvector();
        let hvlen = hvector.len();
        let time = self.get_time();

        // the first 4 bytes stores the time stamp,
        // the time stamp cannot exceed 2^32
        if time > (1 << 32) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_SERIAL));
        }

        let mut buf: Vec<u8> = vec![
            (time & 0xFF) as u8,
            (time >> 8 & 0xFF) as u8,
            (time >> 16 & 0xFF) as u8,
            (time >> 24 & 0xFF) as u8,
        ];

        // next, store one byte which is the length of the hvector
        // this length cannot exceed depth, so we can store it in one byte
        buf.push(hvlen as u8);

        // the next chunck of data stores g2r
        self.get_g2r().serialize(&mut buf, compressed)?;

        // the next chunk of data stores hpoly
        self.get_hpoly().serialize(&mut buf, compressed)?;

        // the next chunk of data stores hvector
        for e in &hvector {
            e.serialize(&mut buf, compressed)?;
        }
        writer.write_all(&buf)?;

        // clean the buf
        {
            let _clear = ClearOnDrop::new(&mut buf);
        }
        assert_eq!(buf, Vec::default());

        Ok(())
    }

    /// Conver a blob into a ssk:
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
    /// Return an error if deserialization fails or invalid ciphersuite
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // the first 4 bytes stores the time stamp,
        // the time stamp cannot exceed 2^30
        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_le_bytes(time);

        // the next byte is the length of hvector
        let mut hvlen = [0u8; 1];

        if reader.read(&mut hvlen).is_err() {
            return Err(Error::new(ErrorKind::InvalidData, ERR_DESERIAL));
        }

        // the next chunck of data stores g2r
        let g2r: PixelG2 = PixelSerDes::deserialize(reader)?;

        // the next chunck of data stores hpoly
        let hpoly: PixelG1 = PixelSerDes::deserialize(reader)?;
        // the next chunck of data stores hvector
        let mut hv: Vec<PixelG1> = vec![];
        for _i in 0..hvlen[0] {
            let tmp: PixelG1 = PixelSerDes::deserialize(reader)?;
            hv.push(tmp)
        }

        Ok(SubSecretKey::construct(u64::from(time), g2r, hpoly, hv))
    }
}

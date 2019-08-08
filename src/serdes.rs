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

type Compressed = bool;

/// Serialization support for pixel structures.
/// This trait is the same as pixel_param::serdes::PixelSerDes.
/// We should think of merge those two traits rather than defining them twice.
pub trait PixelSerDes: Sized {
    /// Serialize a struct to a writer
    /// Whether a point is compressed or not is implicit for the structure:
    /// * public parameters: uncompressed
    /// * public keys: compressed
    /// * proof of possessions: compressed
    /// * secret keys: uncompressed
    /// * signatures: compressed
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()>;

    /// Deserialize a struct; also returns a flag
    /// if the struct was compressed or not.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)>;
}

impl PixelSerDes for PixelG1 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
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
            Ok((g, true))
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => uncompressed mode
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
            Ok((g, false))
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
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
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
            Ok((g, true))
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => uncompressed mode
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
            Ok((g, false))
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
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        let mut buf: Vec<u8> = vec![self.ciphersuite()];
        self.pop().serialize(&mut buf, compressed)?;

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a PoP:
    ///
    /// bytes => `|ciphersuite id | pop |`
    ///
    /// Returns an error if deserialization fails, or if
    /// the pop is not compressed.
    /// The pop's signature must be in the compressed form - strong
    /// unforgebility requires a unique representation of the
    /// signature.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into pop
        let (pop, compressed) = PixelG1::deserialize(reader)?;
        if !compressed {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // finished
        Ok((ProofOfPossession::new(constants[0], pop), compressed))
    }
}

impl PixelSerDes for Signature {
    /// Convert a signature into a blob:
    ///
    /// `|ciphersuite id| time | sigma1 | sigma2 |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    /// Does not check if the signature is verified or not.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // the time stamp cannot exceed 2^30
        let time = self.time();
        if time > (1 << 32) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_SERIAL));
        }

        // first byte is the ciphersuite id
        // the next 4 bytes stores the time stamp,

        let mut buf: Vec<u8> = vec![
            self.ciphersuite(),
            (time & 0xFF) as u8,
            (time >> 8 & 0xFF) as u8,
            (time >> 16 & 0xFF) as u8,
            (time >> 24 & 0xFF) as u8,
        ];

        // serialize sigma1
        self.sigma1().serialize(&mut buf, compressed)?;
        // serialize sigma2
        self.sigma2().serialize(&mut buf, compressed)?;
        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a signature:
    ///
    /// bytes => `|ciphersuite id | time | sigma1 | sigma2 |`
    ///
    /// Returns an error if deserialization fails, or if
    /// the signature is not compressed.
    /// The signature must be in the compressed form - strong
    /// unforgebility requires a unique representation of the
    /// signature.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_le_bytes(time);

        // the time stamp has to be at least 1
        if time == 0 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_TIME_STAMP));
        }

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into sigma1
        let (sigma1, compressed) = PixelG2::deserialize(reader)?;
        if !compressed {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // read into sigma2
        let (sigma2, compressed) = PixelG1::deserialize(reader)?;
        if !compressed {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // finished
        Ok((
            Signature::new(constants[0], u64::from(time), sigma1, sigma2),
            compressed,
        ))
    }
}

impl PixelSerDes for PublicKey {
    /// Convert pk into a blob:
    ///
    /// bytes => `|ciphersuite id| PixelG2 element |`
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.ciphersuite()];
        self.pk().serialize(&mut buf, compressed)?;

        // finished
        writer.write_all(&buf)?;
        Ok(())
    }
    /// Convert blob into a public key:
    ///
    /// `|ciphersuite id| PixelG2 element |` => bytes
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // read into pk
        let (pk, compressed) = PixelG2::deserialize(reader)?;

        // finished
        Ok((PublicKey::new(constants[0], pk), compressed))
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
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.ciphersuite()];

        // next byte is the number of ssk-s
        buf.push(self.ssk_number() as u8);

        // next 64 bytes is the seed for rng
        buf.extend(self.prng().seed().as_ref());

        // followed by serialization of the ssk-s
        for e in &self.ssk_vec() {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
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
        let (ssk, compressed1) = SubSecretKey::deserialize(reader)?;
        ssk_vec.push(ssk);
        for _i in 1..constants[1] {
            let (ssk, compressed2) = SubSecretKey::deserialize(reader)?;
            if compressed1 != compressed2 {
                return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
            }
            ssk_vec.push(ssk);
        }

        // finished
        Ok((
            SecretKey::new(constants[0], ssk_vec[0].time(), ssk_vec, PRNG::new(rngseed)),
            compressed1,
        ))
    }
}

impl PixelSerDes for SubSecretKey {
    /// Conver ssk into a blob:
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
    /// Return an error if serialization fails or time stamp is greater than 2^32-1
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        let hvector = self.hvector();
        let hvlen = hvector.len();
        let time = self.time();

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
        self.g2r().serialize(&mut buf, compressed)?;

        // the next chunk of data stores hpoly
        self.hpoly().serialize(&mut buf, compressed)?;

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
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // the first 4 bytes stores the time stamp
        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_le_bytes(time);
        // the time stamp has to be at least 1
        if time == 0 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_TIME_STAMP));
        }

        // the next byte is the length of hvector
        let mut hvlen = [0u8; 1];

        if reader.read(&mut hvlen).is_err() {
            return Err(Error::new(ErrorKind::InvalidData, ERR_DESERIAL));
        }

        // the next chunck of data stores g2r
        let (g2r, compressed1) = PixelSerDes::deserialize(reader)?;

        // the next chunck of data stores hpoly
        let (hpoly, compressed2) = PixelSerDes::deserialize(reader)?;
        if compressed1 != compressed2 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // the next chunck of data stores hvector
        let mut hv: Vec<PixelG1> = vec![];
        for _i in 0..hvlen[0] {
            let (tmp, compressed2) = PixelSerDes::deserialize(reader)?;
            if compressed1 != compressed2 {
                return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
            }
            hv.push(tmp)
        }

        Ok((
            SubSecretKey::new(u64::from(time), g2r, hpoly, hv),
            compressed1,
        ))
    }
}

use param::VALID_CIPHERSUITE;
use pixel_err::*;
use prng::PRNG;
use std::io::{Error, ErrorKind, Read, Result, Write};
use subkeys::SubSecretKey;
use zeroize::Zeroize;
use PixelG1;
use PixelG2;
use ProofOfPossession;
use PublicKey;
use SecretKey;
use SerDes;
use Signature;

type Compressed = bool;

impl SerDes for ProofOfPossession {
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
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into pop
        let pop = PixelG1::deserialize(reader, compressed)?;

        // finished
        Ok(ProofOfPossession::new(constants[0], pop))
    }
}

impl SerDes for Signature {
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

        // the time stamp cannot exceed 2^32
        let time = self.time();
        if time >= (1 << 32) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_SERIAL));
        }

        // first byte is the ciphersuite id
        // the next 4 bytes stores the time stamp,

        let mut buf: Vec<u8> = vec![
            self.ciphersuite(),
            (time >> 24 & 0xFF) as u8,
            (time >> 16 & 0xFF) as u8,
            (time >> 8 & 0xFF) as u8,
            (time & 0xFF) as u8,
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
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_be_bytes(time);

        // the time stamp has to be at least 1
        if time == 0 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_TIME_STAMP));
        }

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into sigma1
        let sigma1 = PixelG2::deserialize(reader, compressed)?;
        if !compressed {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // read into sigma2
        let sigma2 = PixelG1::deserialize(reader, compressed)?;
        if !compressed {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // finished
        Ok(Signature::new(
            constants[0],
            u64::from(time),
            sigma1,
            sigma2,
        ))
    }
}

impl SerDes for PublicKey {
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
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // read into pk
        let pk = PixelG2::deserialize(reader, compressed)?;

        // finished
        Ok(PublicKey::new(constants[0], pk))
    }
}

impl SerDes for SecretKey {
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

        buf.zeroize();

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
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
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
        let ssk = SubSecretKey::deserialize(reader, compressed)?;
        ssk_vec.push(ssk);
        for _i in 1..constants[1] {
            let ssk = SubSecretKey::deserialize(reader, compressed)?;

            ssk_vec.push(ssk);
        }

        // finished
        Ok(SecretKey::new(
            constants[0],
            ssk_vec[0].time(),
            ssk_vec,
            PRNG::new(rngseed),
        ))
    }
}

impl SerDes for SubSecretKey {
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
            (time >> 24 & 0xFF) as u8,
            (time >> 16 & 0xFF) as u8,
            (time >> 8 & 0xFF) as u8,
            (time & 0xFF) as u8,
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

        buf.zeroize();
        // assert_eq!(buf, Vec::default());

        Ok(())
    }

    /// Conver a blob into a ssk:
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
    /// Return an error if deserialization fails or invalid ciphersuite
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // the first 4 bytes stores the time stamp
        let mut time: [u8; 4] = [0u8; 4];
        reader.read_exact(&mut time)?;
        let time = u32::from_be_bytes(time);
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
        let g2r = SerDes::deserialize(reader, compressed)?;

        // the next chunck of data stores hpoly
        let hpoly = SerDes::deserialize(reader, compressed)?;

        // the next chunck of data stores hvector
        let mut hv: Vec<PixelG1> = vec![];
        for _i in 0..hvlen[0] {
            let tmp = SerDes::deserialize(reader, compressed)?;
            hv.push(tmp)
        }

        Ok(SubSecretKey::new(u64::from(time), g2r, hpoly, hv))
    }
}

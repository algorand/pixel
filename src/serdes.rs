pub use bls_sigs_ref_rs::SerDes;
use keys::{PublicKey, SecretKey, SubSecretKey};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use sig::Signature;
use std::io::{Error, ErrorKind, Read, Result, Write};
use PixelG1;
use PixelG2;

impl SerDes for PubParam {
    /// Convert a public parameter into a blob:
    ///
    /// `|ciphersuite id| depth | g2 | h | hlist |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];

        // Second byte is the time depth
        buf.push(self.get_d() as u8);

        // serialize g2
        self.get_g2().serialize(&mut buf, compressed)?;

        // serialize h
        self.get_h().serialize(&mut buf, compressed)?;

        // serialize hlist
        for e in self.get_hlist().iter() {
            e.serialize(&mut buf, compressed)?;
        }
        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a public parameter:
    ///
    /// bytes => `|ciphersuite id| depth | g2 | h | hlist |`
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // constants stores id and the depth
        let mut constants: [u8; 2] = [0u8; 2];

        reader.read_exact(&mut constants)?;
        let depth = constants[1] as usize;

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into g2
        let g2 = PixelG2::deserialize(reader)?;

        // read into h
        let h = PixelG1::deserialize(reader)?;

        // read into hlist
        let mut hlist: Vec<PixelG1> = vec![];
        // constants[1] stores depth d
        for _i in 0..=depth {
            hlist.push(PixelG1::deserialize(reader)?);
        }

        // finished
        Ok(PubParam::construct(depth, constants[0], g2, h, hlist))
    }
}

impl SerDes for Signature {
    /// Convert a signature into a blob:
    ///
    /// `|ciphersuite id| sigma1 | sigma2 |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    /// Does not check if the signature is verified or not.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];

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
    /// bytes => `|ciphersuite id| sigma1 | sigma2 |`
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

        // read into sigma1
        let sigma1 = PixelG2::deserialize(reader)?;

        // read into sigma2
        let sigma2 = PixelG1::deserialize(reader)?;

        // finished
        Ok(Signature::construct(constants[0], sigma1, sigma2))
    }
}

impl SerDes for PublicKey {
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
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];

        // next byte is the number of ssk-s
        buf.push(self.get_ssk_number() as u8);

        // next 32 bytes is the seed for rng
        buf.extend(self.get_rngseed().as_ref());

        // followed by serialization of the ssk-s
        for e in &self.get_ssk_vec() {
            e.serialize(&mut buf, compressed)?;
        }

        // finished
        writer.write_all(&buf)?;
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
        let mut rngseed: [u8; 32] = [0u8; 32];
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
            rngseed,
        ))
    }
}

impl SerDes for SubSecretKey {
    /// Conver ssk into a blob:
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
    /// Return an error if serialization fails or time stamp is greater than 2^32-1
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        let hvector = self.get_hvector();
        let hvlen = hvector.len();
        let time = self.get_time();

        // the first 4 bytes stores the time stamp,
        // the time stamp cannot exceed 2^30
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
        let g2r: PixelG2 = SerDes::deserialize(reader)?;

        // the next chunck of data stores hpoly
        let hpoly: PixelG1 = SerDes::deserialize(reader)?;
        // the next chunck of data stores hvector
        let mut hv: Vec<PixelG1> = vec![];
        for _i in 0..hvlen[0] {
            let tmp: PixelG1 = SerDes::deserialize(reader)?;
            hv.push(tmp)
        }

        Ok(SubSecretKey::construct(u64::from(time), g2r, hpoly, hv))
    }
}

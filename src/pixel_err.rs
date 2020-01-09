/// A list of error messages.

pub(crate) const ERR_SEED_TOO_SHORT: &str = "The seed length is too short";
pub(crate) const ERR_CIPHERSUITE: &str = "Invalid ciphersuite ID";
pub(crate) const ERR_COMPRESS: &str = "Compressness does not match";
pub(crate) const ERR_TIME_STAMP: &str = "Invalid Time Stamp";
pub(crate) const ERR_TIME_NONE_PREFIX: &str =
    "Current time vector is not a prefix of target vector";
pub(crate) const ERR_SSK_EMPTY: &str = "The sub secret key list is empty";
pub(crate) const ERR_TIME_DEPTH: &str = "Invalid Time Depth";
pub(crate) const ERR_SERIAL: &str = "Fail to convert the element to a blob";
pub(crate) const ERR_DESERIAL: &str = "Fail to convert a blob to the element";

//! This module lists the domain seperators in Pixel.

// prefix of hash_to_field used in hash(msg) -> Fr
pub const DOM_SEP_HASH_TO_MSG: &str = "Pixel hash to message";

// prefix of hash_to_field to generate the randomness for signing
pub const DOM_SEP_SIG: &str = "Pixel randomness for signing";

// prefix of hash_to_field to generate the master key alpha
pub const DOM_SEP_MASTER_KEY: &str = "Pixel master key";

// the info to sample a field element during key initialization
pub const DOM_SEP_SK_INIT: &str = "Pixel secret key init";

// the info to sample a field element during key update
pub const DOM_SEP_SK_UPDATE: &str = "Pixel secret key update";

// the salt and info to update the secret key's prng
pub const DOM_SEP_SK_RERANDOMIZE_SALT: &str = "Pixel secret key rerandomize extract";
pub const DOM_SEP_SK_RERANDOMIZE_INFO: &str = "Pixel secret key rerandomize expand";

// prefix of public key proof of possesion
pub const DOM_SEP_POP: &str = "Pixel public key POP";

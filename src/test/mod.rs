extern crate rand;

/// This module contains deterministic tests, with pre-fixed parameters,
/// and with determinstic, small random numbers, e.g., 1, 2, 3, 4...
/// This test module is only avaliable when public key lies in G2.
#[cfg(debug_assertions)]
#[cfg(feature = "pk_in_g2")]
mod det_test;

/// This module tests basic API's
mod api;

/// This module tests funcationalities of keys.
mod keys;

/// This module tests funcationalities of signing and verification.
mod sig;

/// This module tests serialization and deserialization of the keys and signatures.
mod serdes;

/// This module tests membership testing functions
mod membership;

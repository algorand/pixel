extern crate rand;

/// This module tests basic API's
mod api;

/// This module tests funcationalities of keys.
mod keys;

/// This module tests funcationalities of signing and verification.
mod sig;

/// This module tests serialization and deserialization of the keys and signatures.
mod serdes;

/// This module tests prng fucntions
mod prng;

/// This module tests if zeroize works
mod pixel_zeroize;

/// This module tests ffi functions.
mod ffi;

/// This module tests the getters
mod getter;

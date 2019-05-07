// this is Algorand's implementation of Pixel signature scheme

#![feature(test)]

extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sha2;

#[cfg(test)]
extern crate test;

mod gammafunction;
pub mod keys;
pub mod param;
pub mod pixel;
mod pixel_bench;
mod pixel_test;
mod sign;
mod verify;

// required for hash_to_field
extern crate bigint;
mod util;

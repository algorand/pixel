#![feature(test)]

extern crate ff;
extern crate pairing;
extern crate rand;
mod initkey;
mod keys;
mod param;
mod sign;
mod verify;

#[cfg(test)]
extern crate test;
#[cfg(test)]
mod pixel_bench;

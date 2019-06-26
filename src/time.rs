// this module handles the time stamp that is used

use ff::PrimeField;
use pairing::bls12_381::{Fr, FrRepr};
use std::iter::FromIterator;

/// a time stamp is a unsigned integer of 64 bits
/// starting from 1 to 2^64-1
/// the time stamp cannot be 0
pub type TimeStamp = u64;

/// a struct for TimeVec includes
/// * the vector form of the time which is the path of the time tree
/// * the time stamp itself, for convient access
#[derive(Debug, Clone, PartialEq)]
pub struct TimeVec {
    time: TimeStamp,
    vec: Vec<u64>,
}

impl TimeVec {
    /// get_time() returns the time stamp of a TimeVec
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// get_time_vec() returns the time vector of a TimeVec
    pub fn get_time_vec(&self) -> Vec<u64> {
        self.vec.clone()
    }

    /// returns the length of time vector
    pub fn get_time_vec_len(&self) -> usize {
        self.vec.len()
    }

    /// init() initialize a TimeVec from a TimeStamp
    /// example with depth = 3
    /// assert_eq!(TimeVec::init(1,3).get_time_vec(), vec![]);
    /// assert_eq!(TimeVec::init(2,3).get_time_vec(), vec![1]);
    /// assert_eq!(TimeVec::init(3,3).get_time_vec(), vec![1,1]);
    /// assert_eq!(TimeVec::init(4,3).get_time_vec(), vec![1,2]);
    /// assert_eq!(TimeVec::init(5,3).get_time_vec(), vec![2]);
    /// assert_eq!(TimeVec::init(6,3).get_time_vec(), vec![2,1]);
    /// assert_eq!(TimeVec::init(7,3).get_time_vec(), vec![2,2]);
    pub fn init(t: TimeStamp, depth: u32) -> Self {
        TimeVec {
            time: t,
            vec: time_to_vec(t, depth),
        }
    }

    /// into_fr() extracts the time vector and converts
    /// the vector into the Fr form
    /// code deprecated
    #[allow(dead_code)]
    fn into_fr(&self) -> Vec<Fr> {
        let mut vec: Vec<Fr> = vec![];
        for e in self.get_time_vec() {
            vec.push(Fr::from_repr(FrRepr([e as u64, 0, 0, 0])).unwrap());
        }
        vec
    }

    /// checks if self is a prefix of the other time vector
    /// exmample
    /// use pixel::pixel_api::TimeVec;
    /// let t1 = TimeVec::init(1,3);
    /// let t2 = TimeVec::init(2,3);
    /// assert_eq!(t1.is_prefix(&t2), true);
    pub fn is_prefix(&self, other: &Self) -> bool {
        if self.time >= other.time {
            return false;
        }

        other.vec.starts_with(&self.vec)
    }

    /// subrouting to build the gamma list:
    /// converting a time vector to a list of time vectors.
    ///
    /// example: for time vec \[1\] and d = 4, the list consist all the
    /// vectors that starts with \[1\]
    /// we will need \[1,1,1\], \[1,1,2\], \[1,2\], \[2\]
    pub fn gamma_list(&self, depth: usize) -> Vec<Self> {
        /*
        pseudo code of this function in python
        def gammat(tvec):
           ans = [tvec]
           for i in range(len(tvec)):
              if tvec[i] == 1:
                 print tvec[:i]
                 ans.append(tvec[:i] + [2])
           return ans
        */
        let mut res = Vec::new();
        res.push(self.clone());
        for i in 0..self.vec.len() {
            if self.vec[i] == 1 {
                let mut tmp = Vec::from_iter(self.vec[0..i].iter().cloned());
                tmp.push(2);
                res.insert(
                    1,
                    TimeVec {
                        time: vec_to_time(tmp.clone(), depth as u64),
                        vec: tmp,
                    },
                )
            }
        }
        res
    }
}

// convert time into a vector
fn time_to_vec(time: u64, d: u32) -> Vec<u64> {
    // requires D >=1 and t in {1,2,...,2^D-1}
    assert!(d >= 1, "time_to_vec invalid depth {}", d);
    let max_t = 1 << d;
    assert!(
        time <= max_t && time != 0,
        "time_to_vec invalid time {} > {} for depth {}",
        time,
        max_t,
        d
    );

    /*
        if t==1:
          return []
        if D>0 and t > pow(2,D-1):
           return [2] + time2vec(t-pow(2,D-1),D-1)
        else:
           return [1] + time2vec(t-1,D-1)
    */

    let mut tmp = Vec::new();
    if time == 1 {
        return tmp;
    }
    if d > 0 && time > 2u64.pow(d - 1) {
        tmp = time_to_vec(time - 2u64.pow(d - 1), d - 1);
        tmp.insert(0, 2);
    } else {
        tmp = time_to_vec(time - 1, d - 1);
        tmp.insert(0, 1);
    }

    tmp
}

// convert a vector back to time
fn vec_to_time(mut t_vec: Vec<u64>, d: u64) -> u64 {
    /*
        if tvec == []:
          return 1
          else:
          ti = tvec.pop(0)
          return 1 + (ti-1) * (pow(2,D-1)-1) + vec2time(tvec,D-1)
    */
    assert!(d >= 1, "invalid depth");
    if t_vec == [] {
        return 1;
    } else {
        let tmp: Vec<u64> = t_vec.drain(0..1).collect();
        return 1 + (tmp[0] - 1) * ((1u64 << (d - 1)) - 1) + vec_to_time(t_vec, d - 1);
    }
}

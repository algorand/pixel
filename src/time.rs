// this module handles the time stamp that is used

use pixel_err::*;
use std::iter::FromIterator;

/// a time stamp is a unsigned integer of 64 bits
/// starting from 1 to 2^64-1
/// the time stamp cannot be 0
pub type TimeStamp = u64;

/// a struct for TimeVec includes
/// * the vector form of the time which is the path of the time tree
/// * the time stamp itself, for convenient access
#[derive(Debug, Clone, PartialEq)]
pub struct TimeVec {
    time: TimeStamp, // the actual time stamp, for example 2
    vec: Vec<u64>,   // the path to this time stamp, for example [1, 1]
}

impl TimeVec {
    /// get_time() returns the time stamp of a TimeVec
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// get_time_vec() returns the time vector of a TimeVec
    pub fn get_vector(&self) -> Vec<u64> {
        self.vec.clone()
    }

    /// returns the length of time vector
    pub fn get_vector_len(&self) -> usize {
        self.vec.len()
    }

    /// init() initialize a TimeVec from a TimeStamp
    /// example with depth = 3
    /// assert_eq!(TimeVec::init(1,3).get_time_vec(), vec!\[\]);
    /// assert_eq!(TimeVec::init(2,3).get_time_vec(), vec!\[1\]);
    /// assert_eq!(TimeVec::init(3,3).get_time_vec(), vec!\[1,1\]);
    /// assert_eq!(TimeVec::init(4,3).get_time_vec(), vec!\[1,2\]);
    /// assert_eq!(TimeVec::init(5,3).get_time_vec(), vec!\[2\]);
    /// assert_eq!(TimeVec::init(6,3).get_time_vec(), vec!\[2,1\]);
    /// assert_eq!(TimeVec::init(7,3).get_time_vec(), vec!\[2,2\]);
    /// Returns an error if the time stamp or the depth is invalid
    pub fn init(time: TimeStamp, depth: usize) -> Result<Self, String> {
        let vec = time_to_vec(time, depth)?;
        Ok(TimeVec { time, vec })
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

    /// Gamma list is a subroutine to sk updates.
    /// It converts a time vector to a list of time vectors,
    /// so that any future time stamp is either with in the gamma list,
    /// or is a posterity of the elements in the list.
    /// And propagates error messages if the conversion fails.
    ///
    /// example: for time vec \[1, 1, 1\] and d = 4, the list consists
    /// \[1,1,1\], \[1,1,2\], \[1,2\], \[2\]
    pub fn gamma_list(&self, depth: usize) -> Result<Vec<Self>, String> {
        // pseudo code of this function in python
        // def gammat(tvec):
        //    ans = [tvec]
        //    for i in range(len(tvec)):
        //       if tvec[i] == 1:
        //          print tvec[:i]
        //          ans.append(tvec[:i] + [2])
        //    return ans
        let mut res = Vec::new();
        res.push(self.clone());
        for i in 0..self.vec.len() {
            if self.vec[i] == 1 {
                let mut tmp = Vec::from_iter(self.vec[0..i].iter().cloned());
                tmp.push(2);
                res.insert(
                    1,
                    TimeVec {
                        time: vec_to_time(tmp.clone(), depth)?,
                        vec: tmp,
                    },
                )
            }
        }
        Ok(res)
    }
}

// Convert time into a vector.
// Returns an error if the time stamp or the time depth is invalid.
fn time_to_vec(time: TimeStamp, d: usize) -> Result<Vec<u64>, String> {
    // requires D >=1 and t in {1,2,...,2^D-1}
    if d == 0 {
        #[cfg(debug_assertions)]
        println!("Error in time_to_vec: {}", ERR_TIME_DEPTH);
        return Err(ERR_TIME_DEPTH.to_owned());
    }
    let max_t = 1 << d;
    if time > max_t || time == 0 {
        #[cfg(debug_assertions)]
        println!("Error in time_to_vec: {}", ERR_TIME_STAMP);
        return Err(ERR_TIME_STAMP.to_owned());
    }

    // python code:
    // if t==1:
    //   return []
    // if D>0 and t > pow(2,D-1):
    //    return [2] + time2vec(t-pow(2,D-1),D-1)
    // else:
    //    return [1] + time2vec(t-1,D-1)

    // if t == 1:
    //   return []
    let mut tmp = Vec::new();
    if time == 1 {
        return Ok(tmp);
    }

    // if t > pow(2, D-1), add the right child to the list
    // and process to the right node
    //  1. subtract 2^(d-1) from time
    //  2. add [2] to the vector
    // if t <= pow(2, D-1), add the left child to the list
    // and process to the right node
    //  1. subtract 1 from time
    //  2. add [1] to the vector
    let threshold = 1 << (d - 1);
    if time > threshold {
        tmp = time_to_vec(time - threshold, d - 1)?;
        tmp.insert(0, 2);
    } else {
        tmp = time_to_vec(time - 1, d - 1)?;
        tmp.insert(0, 1);
    }

    Ok(tmp)
}

// Convert a vector back to time.
// Returns an error if time depth is invalid.
fn vec_to_time(mut t_vec: Vec<u64>, d: usize) -> Result<u64, String> {
    // python code:
    //     if tvec == []:
    //       return 1
    //       else:
    //       ti = tvec.pop(0)
    //       return 1 + (ti-1) * (pow(2,D-1)-1) + vec2time(tvec,D-1)

    // requires D >=1 and t in {1,2,...,2^D-1}
    if d == 0 {
        #[cfg(debug_assertions)]
        println!("Error in vec_to_time: {}", ERR_TIME_DEPTH);
        return Err(ERR_TIME_DEPTH.to_owned());
    }
    if t_vec == [] {
        // an empty list is 1
        Ok(1)
    } else {
        // process t_vec[0] recursively
        let tmp: Vec<u64> = t_vec.drain(0..1).collect();
        // if t_vec[0] == 1 => proceed to the left child, so we add the time by 1
        // if t_vec[0] == 1 => proceed to the right child, so we add the time by 2^(d-1)
        Ok(1 + (tmp[0] - 1) * ((1u64 << (d - 1)) - 1) + vec_to_time(t_vec, d - 1)?)
    }
}

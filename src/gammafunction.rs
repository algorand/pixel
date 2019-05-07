// gammafunction module implements the `gamma` function
// that converts a time (as a u64 integer) into a time vector
// that is used to identify the right node on a tree

use ff::{Field, PrimeField};
use pairing::bls12_381::*;
use param::CONST_D;
use std::iter::FromIterator;

// a gamma list constains a list of time vectors,
// as well as a unique time stamp which is the minimum
// time stamp amoung all its members
#[derive(Debug, Clone)]
pub struct GammaList {
    mintime: u64,
    veclist: Vec<TimeVec>,
}

// the struct for time vector also include the
// actual time for simplicity
#[derive(Debug, Clone)]
pub struct TimeVec {
    time: u64,
    vec: Vec<u64>,
}

#[allow(dead_code)]
impl TimeVec {
    pub fn get_time(&self) -> u64 {
        self.time
    }
    pub fn get_time_vec(&self) -> Vec<u64> {
        self.vec.clone()
    }
}

#[allow(dead_code)]
impl GammaList {
    // return the minimum time stamp amount all members
    pub fn get_mintime(&self) -> u64 {
        self.mintime
    }

    // return the list of time vectors
    pub fn get_list(&self) -> Vec<TimeVec> {
        self.veclist.clone()
    }

    // input a time stamp, generate the complete list
    pub fn gen_list(time: u64) -> Self {
        let time_vec = time_to_timevec(time, CONST_D as u32);
        let veclist = gamma_t(time_vec);
        GammaList {
            mintime: time,
            veclist: veclist,
        }
    }

    // update the gamma list w.r.t. a new time
    pub fn update_list(&mut self, newtime: u64) {
        assert!(
            self.mintime < newtime,
            "invalid updating timestamps from current {} to target {}",
            self.mintime,
            newtime
        );

        self.mintime = newtime;
        let time_vec = time_to_timevec(newtime, CONST_D as u32);
        self.veclist = gamma_t(time_vec);
    }
}

// converting time into a time vector object
#[allow(dead_code)]
fn time_to_timevec(time: u64, d: u32) -> TimeVec {
    TimeVec {
        time: time,
        vec: time_to_vec(time, d),
    }
}

// convert time into a vector
#[allow(dead_code)]
pub fn time_to_vec(time: u64, d: u32) -> Vec<u64> {
    /*
        # requires D >=1 and t in {1,2,...,2^D-1}
        if t==1:
          return []
        if D>0 and t > pow(2,D-1):
           return [2] + time2vec(t-pow(2,D-1),D-1)
        else:
           return [1] + time2vec(t-1,D-1)
    */
    assert!(d >= 1, "time_to_vec invalid depth {}", d);
    let max_t = 1 << d;
    assert!(
        time <= max_t && time != 0,
        "time_to_vec invalid time {} > {} for depth {}",
        time,
        max_t,
        d
    );
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

#[allow(dead_code)]
pub fn time_to_fr_vec(time: u64, d: u32) -> Vec<Fr> {
    assert!(d >= 1, "time_to_fr_vec invalid depth {}", d);
    let max_t = 1 << d;
    assert!(
        time <= max_t && time != 0,
        "time_to_fr_vec invalid time {} > {} for depth {}",
        time,
        max_t,
        d
    );
    let v = time_to_vec(time, d);
    let mut res: Vec<Fr> = vec![];
    for e in v {
        res.push(Fr::from_repr(FrRepr([e as u64, 0, 0, 0])).unwrap());
    }
    res
}

#[allow(dead_code)]
pub fn vec_to_time(mut t_vec: Vec<u64>, d: u64) -> u64 {
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
#[allow(dead_code)]
pub fn gamma_t(t_vec: TimeVec) -> Vec<TimeVec> {
    /*
    def gammat(tvec):
       ans = [tvec]
       for i in range(len(tvec)):
          if tvec[i] == 1:
             print tvec[:i]
             ans.append(tvec[:i] + [2])
       return ans
    */
    let mut res = Vec::new();
    res.push(t_vec.clone());
    for i in 0..t_vec.vec.len() {
        if t_vec.vec[i] == 1 {
            let mut tmp = Vec::from_iter(t_vec.vec[0..i].iter().cloned());
            tmp.push(2);
            // if !res.contains(&tmp) {
            //     res.push(tmp)
            // } else {
            //     panic!("Duplicates");
            // }
            res.push(TimeVec {
                time: vec_to_time(tmp.clone(), CONST_D as u64),
                vec: tmp,
            })
        }
    }

    res
}

// #[allow(dead_code)]
// pub fn update_gamma_t(current:Vec<Vec<u64>>,t_vec: Vec<u64>) -> Vec<Vec<u64>> {
//     /*
//     def gammat(tvec):
//        ans = [tvec]
//        for i in range(len(tvec)):
//           if tvec[i] == 1:
//              print tvec[:i]
//              ans.append(tvec[:i] + [2])
//        return ans
//     */
//
//
//
//     let mut res = Vec::new();
// for e in current{
//
//     let t  = gamma_t(e, t_vec);
//
// }
//     res
// }
#[allow(dead_code)]
pub fn gamma_t_fr(t_vec: &Vec<Fr>) -> Vec<Vec<Fr>> {
    let frtwo: Fr = Fr::from_repr(FrRepr([0, 0, 0, 2])).unwrap();
    /*
    def gammat(tvec):
       ans = [tvec]
       for i in range(len(tvec)):
          if tvec[i] == 1:
             print tvec[:i]
             ans.append(tvec[:i] + [2])
       return ans
    */
    let mut res = Vec::new();
    res.push(t_vec.clone());
    for i in 0..t_vec.len() {
        if t_vec[i] == Fr::one() {
            let mut tmp = Vec::from_iter(t_vec[0..i].iter().cloned());
            tmp.push(frtwo);
            if !res.contains(&tmp) {
                res.push(tmp)
            }
        }
    }

    res
}

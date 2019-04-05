use ff::{Field, PrimeField};
use pairing::bls12_381::*;
use param::CONST_D;
use std::iter::FromIterator;

pub struct VecX {
    pub vec_x: Vec<u32>,
    pub msg: Fr,
}

#[derive(Debug, Clone)]
pub struct GammaList {
    time: u32,
    veclist: Vec<Vec<u32>>,
}
#[allow(dead_code)]
impl GammaList {
    pub fn gen_list(time: u32) -> Self {
        let time_vec = time_to_vec(time, CONST_D as u32);
        let veclist = gamma_t(time_vec);
        GammaList {
            time: time,
            veclist: veclist,
        }
    }

    pub fn update_list(&mut self, newtime: u32) {
        if self.time < newtime {
            self.time = newtime;
            let time_vec = time_to_vec(newtime, CONST_D as u32);
            self.veclist = gamma_t(time_vec);
        }
    }

    pub fn print(&self) {
        println!("time: {}", self.time);
        for i in &self.veclist {
            println!("delegates: {}", vec_to_time(i.to_vec(), CONST_D as u32));
        }
    }
}

#[allow(dead_code)]
pub fn vecx_to_vec(input: VecX) -> Vec<Fr> {
    let mut t: Vec<Fr> = Vec::new();
    for i in 0..input.vec_x.len() {
        let tmp = Fr::from_repr(FrRepr([0, 0, 0, input.vec_x[i] as u64])).unwrap();
        t.push(tmp);
    }
    t.push(input.msg);

    t
}
#[allow(dead_code)]
pub fn get_vec_x(time: u32, d: u32, msg: Fr) -> VecX {
    VecX {
        vec_x: time_to_vec(time, d),
        msg: msg,
    }
}
#[allow(dead_code)]
pub fn time_to_vec(time: u32, d: u32) -> Vec<u32> {
    /*
        # requires D >=1 and t in {1,2,...,2^D-1}
        if t==1:
          return []
        if D>0 and t > pow(2,D-1):
           return [2] + time2vec(t-pow(2,D-1),D-1)
        else:
           return [1] + time2vec(t-1,D-1)
    */
    assert!(d >= 1, "invalid depth {}", d);
    let max_t = 1 << d;
    assert!(
        time <= max_t && time != 0,
        "invalid time {} > {} for depth {}",
        time,
        max_t,
        d
    );
    let mut tmp = Vec::new();
    if time == 1 {
        return tmp;
    }
    if d > 0 && time > 2u32.pow(d - 1) {
        tmp = time_to_vec(time - 2u32.pow(d - 1), d - 1);
        tmp.insert(0, 2);
    } else {
        tmp = time_to_vec(time - 1, d - 1);
        tmp.insert(0, 1);
    }

    tmp
}

#[allow(dead_code)]
pub fn time_to_fr_vec(time: u32, d: u32) -> Vec<Fr> {
    let v = time_to_vec(time, d);
    let mut res: Vec<Fr> = vec![];
    for e in v {
        res.push(Fr::from_repr(FrRepr([e as u64, 0, 0, 0])).unwrap());
    }
    res
}

#[allow(dead_code)]
pub fn vec_to_time(mut t_vec: Vec<u32>, d: u32) -> u32 {
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
        let tmp: Vec<u32> = t_vec.drain(0..1).collect();
        return 1 + (tmp[0] - 1) * (2u32.pow(d - 1) - 1) + vec_to_time(t_vec, d - 1);
    }
}
#[allow(dead_code)]
pub fn gamma_t(t_vec: Vec<u32>) -> Vec<Vec<u32>> {
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
        if t_vec[i] == 1 {
            let mut tmp = Vec::from_iter(t_vec[0..i].iter().cloned());
            tmp.push(2);
            if !res.contains(&tmp) {
                res.push(tmp)
            } else {
                panic!("Duplicates");
            }
        }
    }

    res
}

// #[allow(dead_code)]
// pub fn update_gamma_t(current:Vec<Vec<u32>>,t_vec: Vec<u32>) -> Vec<Vec<u32>> {
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

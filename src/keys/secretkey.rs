use super::subsecretkey::SubSecretKey;
use gammafunction::{gamma_t, time_to_timevec, *};
use param::{PubParam, CONST_D};
use rand::ChaChaRng;
// the secret key is a list of SubSecretKeys
// the length is arbitrary
#[derive(Debug, Clone)]
pub struct SecretKey {
    pub time: u64, // smallest timestamp for all subkeys
    pub ssk: Vec<SubSecretKey>,
}

impl SecretKey {
    pub fn init() -> Self {
        SecretKey {
            time: 1,
            ssk: Vec::new(),
        }
    }
    pub fn delegate(&self, pp: &PubParam, time: u64) -> Self {
        let t = GammaList::gen_list(time as u32);
        let mut rng = ChaChaRng::new_unseeded();
        println!("{:?}", t);
        let mut newsk: Vec<SubSecretKey> = vec![];
        let sk0 = self.ssk[0].clone();
        for e in t.veclist {
            let ssk = sk0.subkey_delegate(
                &pp,
                e.time as u64, //x_prime: &Vec<u32>,
                &mut rng,
            );
            newsk.push(ssk);
        }
        //self.clone()
        SecretKey {
            time: time,
            ssk: newsk,
        }
    }
    pub fn optimized_delegate(&self, pp: &PubParam, time: u64) -> Self {
        let newlist = GammaList::gen_list(time as u32);
        let mut rng = ChaChaRng::new_unseeded();
        let mut newsk: Vec<SubSecretKey> = vec![];
        let currentsk = self.clone();
        for t in newlist.veclist {
            let mut flag = false;
            for i in 0..currentsk.ssk.len() {
                if t.time == currentsk.ssk[i].time as u32 {
                    newsk.push(currentsk.ssk[i].clone());
                    flag = true;
                }
            }
            if flag == false {
                // let mut void = SubSecretKey::init();
                // void.time = t.time as u64;
                // newsk.push(void);
                let sk0 = get_closest_ssk(self, t.time as u64);
                //                let sk0 = self.ssk[0].clone();
                let ssk = sk0.subkey_delegate(
                    &pp,
                    t.time as u64, //x_prime: &Vec<u32>,
                    &mut rng,
                );
                newsk.push(ssk);
            }
        }
        SecretKey {
            time: time,
            ssk: newsk,
        }
        //    self.clone()
    }
}

// returning the closest ssk so that the delegation cost is minimum
fn get_closest_ssk(sk: &SecretKey, tar_time: u64) -> SubSecretKey {
    assert!(
        sk.time < tar_time,
        "invalid current time {} vs target time {}",
        sk.time,
        tar_time
    );
    let mut res = sk.ssk[0];
    for ssk in sk.clone().ssk {
        if ssk.time > res.time && ssk.time < tar_time {
            res = ssk;
        }
    }
    res
}

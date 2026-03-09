use crate::ELEMENT_BYTE_SIZE;
use crypto_bigint::{Limb, Word};
use kaspa_math::Uint3072;
use serde::{Deserialize, Serialize};
use std::ops::{DivAssign, MulAssign};
const PRIME_DIFF: Word = 1103717;

const MODULUS: crypto_bigint::Odd<crypto_bigint::U3072> = crypto_bigint::Odd::from_le_hex(
    "9B28EFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U3072(crypto_bigint::U3072);
impl U3072 {
    #[inline(always)]
    pub const fn zero() -> Self {
        Self(crypto_bigint::U3072::ZERO)
    }

    #[inline(always)]
    pub const fn one() -> Self {
        Self(crypto_bigint::U3072::ONE)
    }

    #[inline(always)]
    #[must_use]
    pub fn is_overflow(&self) -> bool {
        // If the smallest limb is smaller than MAX-PRIME_DIFF then it is not overflown.
        if self.0.as_words()[0] <= Word::MAX - PRIME_DIFF {
            return false;
        }
        // If all other limbs == MAX it is overflown.
        self.0.as_words()[1..].iter().all(|&limb| limb == Word::MAX)
    }

    #[inline(always)]
    pub fn from_le_bytes(bytes: [u8; ELEMENT_BYTE_SIZE]) -> Self {
        Self(crypto_bigint::U3072::from_le_slice(&bytes))
    }

    #[inline(always)]
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; ELEMENT_BYTE_SIZE] {
        self.0.to_le_bytes().into()
    }

    #[inline(always)]
    #[must_use]
    pub(super) fn to_le_u64_limbs(self) -> [u64; 48] {
        let bytes = self.0.to_le_bytes();
        let mut arr = [0u64; 48];
        bytes.as_chunks().0.iter().zip(arr.iter_mut()).for_each(|(&chunk, limb)| {
            *limb = u64::from_le_bytes(chunk);
        });
        arr
    }

    #[inline(always)]
    #[must_use]
    pub(super) fn from_le_u64_limbs(arr: [u64; 48]) -> Self {
        let mut bytes = [0u8; 384];
        bytes.chunks_exact_mut(8).zip(arr.iter()).for_each(|(chunk, &limb)| {
            chunk.copy_from_slice(&limb.to_le_bytes());
        });
        Self::from_le_bytes(bytes)
    }

    fn mul(&mut self, other: &U3072) {
        /*
           Optimization: short-circuit when LHS is one
               - This case is especially frequent during parallel reduce operation where the identity (one) is used for each sub-computation (at the LHS)
               - If self ≠ one, the comparison should exit early, otherwise if they are equal -- we gain much more than we lose
               - Benchmarks show that general performance remains the same while parallel reduction gains ~35%
        */
        if *self == Self::one() {
            *self = *other;
            return;
        }
        *self = U3072(self.0.mul_mod_special(&other.0, Limb(PRIME_DIFF)));
    }

    #[must_use]
    fn inverse(self) -> Self {
        // The only value that doesn't have a multiplicative inverse is 0, and 0/x is 0.
        Self(self.0.invert_odd_mod_vartime(&MODULUS).unwrap_or(self.0))
    }

    fn div(&mut self, other: &Self) {
        let inv = other.inverse();
        self.mul(&inv);
    }
}

impl Serialize for U3072 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Uint3072(self.to_le_u64_limbs()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for U3072 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u = Uint3072::deserialize(deserializer)?;
        Ok(U3072::from_le_u64_limbs(u.0))
    }
}

impl From<U3072> for Uint3072 {
    fn from(u: U3072) -> Self {
        Uint3072(u.to_le_u64_limbs())
    }
}

impl DivAssign for U3072 {
    #[inline(always)]
    fn div_assign(&mut self, rhs: Self) {
        self.div(&rhs);
    }
}

impl MulAssign for U3072 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.mul(&rhs);
    }
}

impl Default for U3072 {
    #[inline(always)]
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use crate::u3072::U3072;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_modulus() {
        let mut p = crypto_bigint::U3072::MAX;
        p.as_mut_words()[0] -= super::PRIME_DIFF - 1;
        assert_eq!(p, super::MODULUS.get());
    }

    #[test]
    fn test_inverse() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        for _ in 0..5 {
            let mut element = U3072::zero();
            rng.fill(&mut element.0.as_mut_words()[..]);
            let inv = element.inverse();
            let again = inv.inverse();
            assert_eq!(again, element);
            element.mul(&inv);
            assert_eq!(element, U3072::one());
        }
    }

    fn is_one(v: &U3072) -> bool {
        *v == U3072::one()
    }

    // Otherwise this test it too long
    #[cfg(feature = "rayon")]
    #[test]
    fn exhuastive_test_div_overflow() {
        use super::PRIME_DIFF;
        use rayon::prelude::*;

        let max = U3072(crypto_bigint::U3072::MAX);
        let one = U3072::one();
        // Exhaustively test all the 1,103,717 overflowing numbers.
        (0..PRIME_DIFF).into_par_iter().for_each(|i| {
            let overflown = {
                let mut overflown = max;
                overflown.0.as_mut_words()[0] = crypto_bigint::Word::MAX - i;
                overflown
            };
            {
                let mut overflown_copy = overflown;
                overflown_copy /= one;
                let reduced = overflown_copy.to_le_u64_limbs();
                assert_eq!(reduced[0], PRIME_DIFF - i - 1);
                assert!(reduced[1..].iter().all(|&x| x == 0));
            }

            // Zero doesn't have a modular inverse
            if i != PRIME_DIFF - 1 {
                let mut lhs = overflown;
                let rhs = overflown;
                lhs /= rhs;
                assert!(is_one(&lhs), "i: {i}, lhs: {lhs:?}");
            }
        });
    }

    #[test]
    fn test_mul_max() {
        let mut max = U3072(super::MODULUS.get());
        max.0.as_mut_words()[0] -= 1;
        let copy_max = max;
        max *= copy_max;
        assert!(is_one(&max), "(p-1)*(p-1) mod p should equal 1");
    }

    #[test]
    fn test_mul_div() {
        const LOOPS: usize = 64;

        let mut rng = ChaCha8Rng::seed_from_u64(1);

        let list: Vec<_> = (0..LOOPS)
            .map(|_| {
                let mut element = U3072::zero();
                rng.fill(&mut element.0.as_mut_words()[..]);
                element
            })
            .collect();

        let mut start = U3072::one();
        for &elem in list.iter() {
            start *= elem;
        }
        assert!(!is_one(&start));

        for &elem in list.iter() {
            start /= elem;
        }
        assert!(is_one(&start));
    }

    #[test]
    fn test_inverse_edge_case() {
        #[rustfmt::skip]
        let orig = U3072::from_le_u64_limbs([
            7122228832992001076, 984226626229791276, 7630161757215403889, 6284986028532537849, 8045609952094061025,
            11960578682873843289, 13746438324198032094, 13918942278011779234, 17733507388171786846, 10563242470999117317,
            17037155475664456442, 17937456968131788544, 12599342294785769540, 13386260146859547870, 2817582499516127913,
            652557987984108933, 9669847560665129471, 17711760030167214508, 5376140856964249866, 18051557786492143716,
            2482926987284881227, 8605482545261324676, 7878786448874819977, 1266815984192471985, 2678516262590404672,
            14004775981272003760, 10357003870690124643, 2730710396948079405, 4635754375072562978, 13656184258619915136,
            803512205739688286, 11844116904145642840, 5760653310472302601, 15069027324939031326, 14913021043324743434,
            17567013163360751106, 6302557725767759643, 17458497366820989801, 3410551217786514778, 14182717432968305815,
            12471950523812677269, 2294197765573979691, 3220941588656114052, 605606616684921311, 1440136155000853957,
            16361481774333736133, 11385241783616172231, 13968855456762740410,
        ]);
        let inv = orig.inverse();
        assert_eq!(inv.inverse(), orig);
    }
}

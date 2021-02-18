use std::fmt::{Debug, Formatter};
use std::fmt;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::field::field::Field;

/// P = 2**64 - EPSILON
///   = 2**64 - 9 * 2**28 + 1
///   = 2**28 * (2**36 - 9) + 1
const P: u64 = 18446744071293632513;

/// EPSILON = 9 * 2**28 - 1
const EPSILON: u64 = 2415919103;

const GENERATOR: CrandallField = CrandallField(5);
const TWO_ADICITY: usize = 28;
const POWER_OF_TWO_GENERATOR: CrandallField = CrandallField(10281950781551402419);

/// A field designed for use with the Crandall reduction algorithm.
// TODO: [Partial]Eq should compare canonical representations.
#[derive(Copy, Clone)]
pub struct CrandallField(pub u64);

impl PartialEq for CrandallField {
    fn eq(&self, other: &Self) -> bool {
        self.to_canonical_u64() == other.to_canonical_u64()
    }
}

impl Eq for CrandallField {}

impl Debug for CrandallField {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Field for CrandallField {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
    const NEG_ONE: Self = Self(P - 1);

    #[inline(always)]
    fn sq(&self) -> Self {
        *self * *self
    }

    #[inline(always)]
    fn cube(&self) -> Self {
        *self * *self * *self
    }

    fn try_inverse(&self) -> Option<Self> {
        unimplemented!()
    }

    fn primitive_root_of_unity(n_power: usize) -> Self {
        assert!(n_power <= TWO_ADICITY);
        let base = POWER_OF_TWO_GENERATOR;
        base.exp(CrandallField(1u64 << (TWO_ADICITY - n_power)))
    }

    fn cyclic_subgroup_known_order(generator: Self, order: usize) -> Vec<Self> {
        let mut subgroup = Vec::new();
        let mut current = Self::ONE;
        for _i in 0..order {
            subgroup.push(current);
            current = current * generator;
        }
        subgroup
    }

    #[inline(always)]
    fn to_canonical_u64(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn from_canonical_u64(n: u64) -> Self {
        Self(n)
    }
}

impl Neg for CrandallField {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        let (diff, under) = P.overflowing_sub(self.0);
        Self(diff.overflowing_add((under as u64) * P).0)
    }
}

impl Add for CrandallField {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let (sum, over) = self.0.overflowing_add(rhs.0);
        Self(sum.overflowing_sub((over as u64) * P).0)
    }
}

impl AddAssign for CrandallField {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for CrandallField {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let (diff, under) = self.0.overflowing_sub(rhs.0);
        Self(diff.overflowing_add((under as u64) * P).0)
    }
}

impl SubAssign for CrandallField {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for CrandallField {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        reduce128((self.0 as u128) * (rhs.0 as u128))
    }
}

impl MulAssign for CrandallField {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for CrandallField {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl DivAssign for CrandallField {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

#[inline(always)]
fn reduce64(x: u64) -> u64 {
    // TODO: slow? try cond sub
    // x % P
    let over = x > P;
    x - (over as u64) * P
}

/// no final reduction
#[inline(always)]
fn reduce128(x: u128) -> CrandallField {
    // This is Crandall's algorithm. When we have some high-order bits (i.e. with a weight of 2^64),
    // we convert them to low-order bits by multiplying by EPSILON (the logic is a simple
    // generalization of Mersenne prime reduction). The first time we do this, the product will take
    // ~96 bits, so we still have some high-order bits. But when we repeat this another time, the
    // product will fit in 64 bits.
    let (lo_1, hi_1) = split(x);
    let (lo_2, hi_2) = split((EPSILON as u128) * (hi_1 as u128) + (lo_1 as u128));
    let lo_3 = hi_2 * EPSILON;

    CrandallField(lo_2) + CrandallField(lo_3)
}

#[inline(always)]
fn split(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}

#[cfg(test)]
mod tests {
}

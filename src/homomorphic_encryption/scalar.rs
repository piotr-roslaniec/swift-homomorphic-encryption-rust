// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains helper methods for constant-time operation on scalars.
// TODO: Currently only needed by CuckooTable

use std::{
    fmt::Debug,
    ops::{Add, Shr, Sub},
};

/// Computes `ceil(value / divisor)`.
///
/// # Parameters
/// - `value`: The number we divide.
/// - `divisor`: The number to divide by.
/// - `variable_time`: Must be `true`, indicating this value and `divisor` are leaked through
///   timing.
///
/// # Returns
/// `ceil(value / divisor)`.
///
/// # Warning
/// Leaks this value and `divisor` through timing.
pub fn dividing_ceil(value: i64, divisor: i64, variable_time: bool) -> i64 {
    assert!(variable_time);
    assert_ne!(divisor, 0);
    if value > 0 && divisor > 0 {
        return (value - 1) / divisor + 1;
    }
    if value < 0 && divisor < 0 {
        return (value + 1) / divisor + 1;
    }
    value / divisor
}

/// Scalar type for ``PolyRq`` polynomial coefficients.
pub trait ScalarType:
    PartialEq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Send
    + Sized
    + Clone
    + Copy
    + Debug
    + Default
    + PartialEq
    + Ord
    + Shr<i32, Output = Self>
{
    fn subtract_if_exceeds(&self, modulus: &Self) -> Self {
        // Guard against difference mask fails
        assert!(*self <= (Self::max_value() >> 1) + *modulus);
        let difference = *self - *modulus;
        let mask = 0i32 - (difference >> (self.bit_width() as i32 - 1)).to_i32();
        difference - modulus.bitwise_and(&(Self::from_i32(mask)))
    }

    /// Computes `-self mod modulus`.
    ///
    /// `self` must be in `[0, modulus-1]`.
    ///
    /// # Parameters
    ///
    /// - `modulus`: The modulus.
    ///
    /// # Returns
    ///
    /// `-self mod modulus`.
    fn negate_mod(&self, modulus: &Self) -> Self;

    /// Computes modular exponentiation.
    ///
    /// Computes `self` raised to the power of `exponent` mod `modulus`, i.e., `self^exponent mod
    /// modulus`.
    ///
    /// # Parameters
    ///
    /// - `exponent`: The exponent.
    /// - `modulus`: The modulus.
    /// - `variable_time`: Must be `true`. Setting to `true` causes `modulus` and `exponent` to be
    ///   leaked through timing.
    ///
    /// # Returns
    ///
    /// - `self^exponent mod modulus`
    ///
    /// # Warning
    ///
    /// - Leaks `self`, `exponent`, `modulus` through timing.
    fn pow_mod(&self, _exponent: &Self, _modulus: &Self, variable_time: bool) -> Self {
        assert!(variable_time);
        todo!();
        // if exponent == 0 {
        //     return 1
        // }
        // let base = self;
        // let exponent = exponent;
    }

    fn add_mod(&self, other: &Self, modulus: &Self) -> Self {
        todo!();
    }

    fn sub_mod(&self, other: &Self, modulus: &Self) -> Self {
        todo!();
    }

    fn max_value() -> Self;
    fn bit_width(&self) -> u8;
    fn bitwise_and(&self, other: &Self) -> Self;

    fn to_i32(&self) -> i32;
    fn from_i32(value: i32) -> Self;
}

impl ScalarType for u32 {
    fn negate_mod(&self, modulus: &u32) -> Self {
        assert!(self < modulus);
        (modulus - self).subtract_if_exceeds(modulus)
    }

    fn max_value() -> Self {
        u32::MAX
    }

    fn bit_width(&self) -> u8 {
        32
    }

    fn bitwise_and(&self, other: &Self) -> Self {
        self & other
    }

    fn to_i32(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> Self {
        value as Self
    }
}

impl ScalarType for u64 {
    fn negate_mod(&self, modulus: &u64) -> Self {
        assert!(self < modulus);
        (modulus - self).subtract_if_exceeds(modulus)
    }

    fn max_value() -> Self {
        u64::MAX
    }

    fn bit_width(&self) -> u8 {
        64
    }

    fn bitwise_and(&self, other: &Self) -> Self {
        self & other
    }

    fn to_i32(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> Self {
        value as Self
    }
}

impl ScalarType for usize {
    fn negate_mod(&self, modulus: &usize) -> Self {
        assert!(self < modulus);
        (modulus - self).subtract_if_exceeds(modulus)
    }

    fn max_value() -> Self {
        usize::MAX
    }

    fn bit_width(&self) -> u8 {
        32
    }

    fn bitwise_and(&self, other: &Self) -> Self {
        self & other
    }

    fn to_i32(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> Self {
        value as Self
    }
}

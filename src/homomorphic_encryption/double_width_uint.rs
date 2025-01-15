use derive_more::{BitAnd, BitOr, BitXor, Not, Shl, Shr};
use ruint::aliases::{U128, U16, U256, U32, U64};

/// Generic double-width unsigned integer
#[derive(Debug, Clone, Copy, PartialEq, Eq, BitAnd, BitOr, BitXor, Not, Shl, Shr, Default)]
pub struct DoubleWidthUInt<B>
where
    B: FixedWidthUInt,
{
    pub high: B,
    pub low: B,
}

impl<B> DoubleWidthUInt<B>
where
    B: FixedWidthUInt,
{
    /// Create a new DoubleWidthUInt from high and low parts
    pub fn new(high: B, low: B) -> Self {
        Self { high, low }
    }

    /// Create a `DoubleWidthUInt` with both `high` and `low` parts set to zero.
    fn zero() -> Self {
        Self { high: B::ZERO, low: B::ZERO }
    }
}

/// Trait for fixed-width unsigned integers
pub trait FixedWidthUInt:
    Sized
    + Copy
    + std::fmt::Debug
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::Mul<Output = Self>
    + std::ops::Div<Output = Self>
    + std::ops::Rem<Output = Self>
{
    const ZERO: Self;
    const MAX: Self;

    /// Create a value from a `u64`.
    fn from_u64(value: u64) -> Self;

    /// Convert the value to a `u64`.
    fn to_u64(self) -> u64;

    /// Perform addition with overflow.
    fn overflowing_add(self, rhs: Self) -> (Self, bool);
}

/// Macro to implement the FixedWidthUInt trait for ruint types.
macro_rules! impl_fixed_width_uint {
    ($type:ty) => {
        impl FixedWidthUInt for $type {
            const MAX: Self = <$type>::MAX;
            const ZERO: Self = <$type>::ZERO;

            fn from_u64(value: u64) -> Self {
                <$type>::from(value)
            }

            fn to_u64(self) -> u64 {
                self.try_into().unwrap_or(u64::MAX)
            }

            fn overflowing_add(self, rhs: Self) -> (Self, bool) {
                let (result, overflow) = self.overflowing_add(rhs);
                (result, overflow)
            }
        }
    };
}

impl_fixed_width_uint!(U16);
impl_fixed_width_uint!(U32);
impl_fixed_width_uint!(U64);
impl_fixed_width_uint!(U128);
impl_fixed_width_uint!(U256);

impl<B> std::fmt::Display for DoubleWidthUInt<B>
where
    B: FixedWidthUInt,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The number represented as a double-width integer can be computed as:
        // result = (high << BITS_IN_B) + low
        let bits_in_b = B::MAX.to_u64().count_ones(); // Get the number of bits in base type `B`.
        let high_shifted = (self.high.to_u64() as u128) << bits_in_b; // Shift the high part.
        let low_value = self.low.to_u64() as u128; // Convert low value to `u128`.
        let result = high_shifted + low_value; // Combine high and low parts as a single number.

        write!(f, "{}", result)
    }
}

#[cfg(test)]
mod tests {
    use ruint::aliases::{U128, U16, U64};

    use super::DoubleWidthUInt;

    #[test]
    fn test_from_parts() {
        let value = DoubleWidthUInt::new(U64::from(1u64), U64::from(2u64));

        // Check high and low part accessors.
        assert_eq!(value.high, U64::from(1u64));
        assert_eq!(value.low, U64::from(2u64));
    }

    #[test]
    fn test_display_trait() {
        let value = DoubleWidthUInt::new(U64::from(1u64), U64::from(2u64));
        assert_eq!(value.to_string(), "18446744073709551618");

        let value = DoubleWidthUInt::new(U64::from(123u64), U64::from(456u64));
        let expected: U128 = (U128::from(123u64) << 64) + U128::from(456u64);
        assert_eq!(value.to_string(), expected.to_string());
    }

    #[test]
    fn test_debug_trait() {
        let value = DoubleWidthUInt::new(U64::from(1u64), U64::from(2u64));
        let debug_str = format!("{:?}", value);
        assert_eq!(debug_str, "DoubleWidthUInt { high: 1, low: 2 }");
    }

    #[test]
    fn test_zero_value() {
        let value: DoubleWidthUInt<U64> = DoubleWidthUInt::zero();

        assert_eq!(value.high, U64::ZERO);
        assert_eq!(value.low, U64::ZERO);
        assert_eq!(value.to_string(), "0");
    }

    #[test]
    fn test_large_values() {
        let value = DoubleWidthUInt::new(U64::MAX, U64::MAX);
        let expected: U128 = (U128::from(U64::MAX) << 64) + U128::from(U64::MAX);
        assert_eq!(value.to_string(), expected.to_string());
    }

    #[test]
    fn test_with_u16_base_type() {
        let value = DoubleWidthUInt::new(U16::MAX, U16::MAX);
        let expected: U64 = (U64::from(U16::MAX) << 16) | U64::from(U16::MAX);
        assert_eq!(value.to_string(), expected.to_string());

        let debug_str = format!("{:?}", value);
        assert_eq!(debug_str, "DoubleWidthUInt { high: 65535, low: 65535 }");
    }

    #[test]
    fn test_bitwise_and() {
        let value1 = DoubleWidthUInt::new(U64::from(0b1010u64), U64::from(0b1100u64));
        let value2 = DoubleWidthUInt::new(U64::from(0b0110u64), U64::from(0b1010u64));
        let result = value1 & value2;

        assert_eq!(result.high, U64::from(0b0010u64));
        assert_eq!(result.low, U64::from(0b1000u64));
    }

    #[test]
    fn test_bitwise_or() {
        let value1 = DoubleWidthUInt::new(U64::from(0b1010u64), U64::from(0b1100u64));
        let value2 = DoubleWidthUInt::new(U64::from(0b0110u64), U64::from(0b1010u64));
        let result = value1 | value2;

        assert_eq!(result.high, U64::from(0b1110u64));
        assert_eq!(result.low, U64::from(0b1110u64));
    }

    #[test]
    fn test_bitwise_xor() {
        let value1 = DoubleWidthUInt::new(U64::from(0b1010u64), U64::from(0b1100u64));
        let value2 = DoubleWidthUInt::new(U64::from(0b0110u64), U64::from(0b1010u64));
        let result = value1 ^ value2;

        assert_eq!(result.high, U64::from(0b1100u64));
        assert_eq!(result.low, U64::from(0b0110u64));
    }

    #[test]
    fn test_bitwise_not() {
        let value = DoubleWidthUInt::new(U64::from(0b1010u64), U64::from(0b1100u64));
        let result = !value;

        assert_eq!(result.high, !U64::from(0b1010u64));
        assert_eq!(result.low, !U64::from(0b1100u64));
    }

    #[test]
    fn test_left_shift() {
        let value = DoubleWidthUInt::new(U64::from(1u64), U64::from(1u64));
        let result = value << 1;

        assert_eq!(result.high, U64::from(2u64));
        assert_eq!(result.low, U64::from(2u64));
    }

    #[test]
    fn test_right_shift() {
        let value = DoubleWidthUInt::new(U64::from(2u64), U64::from(128u64));
        let result = value >> 1;

        assert_eq!(result.high, U64::from(1u64));
        assert_eq!(result.low, U64::from(64u64));
    }
}

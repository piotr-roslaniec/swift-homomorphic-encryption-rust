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

use std::ops::Index;

use eyre::Result;
use thiserror::Error;

use crate::homomorphic_encryption::{poly_rq::poly::PolyRq, scalar::ScalarType};

/// Iterates over coefficients of a polynomial, applying a Galois transformation.
pub struct GaloisCoeffIterator {
    /// Degree of the RLWE polynomial.
    degree: u32,
    /// `log2(degree)`.
    log2_degree: u32,
    /// `x % degree == x & mod_degree_mask`, because `degree` is a power of two
    mod_degree_mask: u32,
    /// Power in transformation `f(x) -> f(x^{galois_element})`.
    galois_element: u32,
    /// Simple incrementing index of the iterator in `[0, degree)`.
    iter_index: u32,
    /// `iter_index * galois_element`.
    raw_out_index: u32,
    /// Raw output index mod-reduced to `[0, degree)`.
    out_index: u32,
}

impl GaloisCoeffIterator {
    pub fn new(degree: u32, galois_element: u32) -> Self {
        galois_element.is_valid_galois_element(degree);
        Self {
            degree,
            log2_degree: degree.ilog2(),
            mod_degree_mask: degree - 1,
            galois_element,
            iter_index: 0,
            raw_out_index: 0,
            out_index: 0,
        }
    }
}

impl Iterator for GaloisCoeffIterator {
    type Item = (bool, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.iter_index < self.degree {
            // Use x^degree == -1 mod (x^degree + 1)
            // floor(out_raw_index / degree) odd => negate coefficient
            let negate = (self.raw_out_index >> self.log2_degree) & 1 != 0;
            let ret = (negate, self.out_index);
            self.iter_index += 1;
            self.raw_out_index += self.galois_element;
            self.out_index = self.raw_out_index & self.mod_degree_mask;
            Some(ret)
        } else {
            None
        }
    }
}

///  Iterates over evaluation points of a polynomial, applying a Galois transformation.
pub struct GaloisEvalIterator {
    /// Degree of the RLWE polynomial.
    degree: u32,
    /// `log2(degree)`.
    log2_degree: u32,
    /// `x % degree == x & mod_degree_mask`, because `degree` is a power of two
    mod_degree_mask: u32,
    /// Power in transformation `f(x) -> f(x^{galois_element})`.
    galois_element: u32,
    /// Simple incrementing index of the iterator in `[0, degree)`.
    iter_index: u32,
}

impl GaloisEvalIterator {
    pub fn new(degree: u32, galois_element: u32) -> Self {
        galois_element.is_valid_galois_element(degree);
        Self {
            degree,
            log2_degree: degree.ilog2(),
            mod_degree_mask: degree - 1,
            galois_element,
            iter_index: 0,
        }
    }
}

impl Iterator for GaloisEvalIterator {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.iter_index < self.degree {
            let reversed =
                (self.iter_index + self.degree).reverse_bits() >> (32 - (self.log2_degree + 1));
            let mut index_raw = (self.galois_element * reversed) >> 1;
            index_raw &= self.mod_degree_mask;
            self.iter_index += 1;
            Some(index_raw.reverse_bits() >> (32 - self.log2_degree))
        } else {
            None
        }
    }
}

pub trait FixedWidthInteger {
    fn is_valid_galois_element(&self, degree: u32) -> bool;
}

impl FixedWidthInteger for u32 {
    fn is_valid_galois_element(&self, degree: u32) -> bool {
        degree.is_power_of_two() && *self % 2 != 0 && *self < (degree << 1) && *self > 1
    }
}

impl<Type> PolyRq<Type>
where
    Type: ScalarType,
{
    /// Applies a Galois transformation, also known as a Frobenius transformation.
    ///
    /// The Galois transformation with Galois element `p` transforms the polynomial `f(x)` to
    /// `f(x^p)`.
    ///
    /// # Parameters
    /// - `element`: Galois element of the transformation.
    ///
    /// # Returns
    /// The polynomial after applying the Galois transformation.
    pub fn apply_galois(&self, element: u32) -> Self {
        assert!(element.is_valid_galois_element(self.degree()));
        let mut output = self.clone();
        for (rns_index, modulus) in self.moduli().iter().enumerate() {
            let mut iterator = GaloisCoeffIterator::new(self.degree(), element);
            let data_indices = self.data.row_indices(rns_index);
            let output_index = |column: usize| self.data.index(rns_index, column);
            for data_index in data_indices {
                if let Some((negate, out_index)) = iterator.next() {
                    let out_idx = output_index(out_index as usize);
                    if negate {
                        let negated = self.data[data_index]
                            .iter()
                            .map(|x| x.negate_mod(modulus))
                            .collect::<Vec<_>>();
                        output.data[out_idx].copy_from_slice(&negated);
                    } else {
                        output.data[out_idx].copy_from_slice(&self.data[data_index]);
                    }
                } else {
                    panic!("GaloisCoeffIterator goes out of index");
                }
            }
        }
        output
    }
}

#[derive(Error, Debug)]
pub enum GaloisElementError {
    /// Invalid degree.
    #[error("Invalid degree: {0}")]
    InvalidDegree(u32),
    /// Invalid rotation step.
    #[error("Invalid rotation step: step {step}, degree {degree}")]
    InvalidRotationStep { step: i32, degree: u32 },
}

/// Utilities for generating Galois elements.
pub struct GaloisElement {}

impl GaloisElement {
    pub const GENERATOR: u32 = 3;

    /// Returns the Galois element to swap rows.
    ///
    /// # Parameters
    ///
    /// - `degree`: Polynomial degree
    ///
    /// # Returns
    ///
    /// The galois element to swap rows.
    pub fn swapping_rows(degree: u32) -> u32 {
        (degree << 1) - 1
    }

    /// Returns the Galois element for column rotation by `step`.
    ///
    /// # Parameters
    /// - `step`: Number of slots to rotate. Negative values indicate a left rotation, and positive
    ///   values indicate right rotation. Must have absolute value in `[1, N / 2 - 1]`.
    /// - `degree`: The RLWE ring dimension `N`.
    ///
    /// # Returns
    /// The Galois element for column rotation by `step`.
    ///
    /// # Errors
    /// Returns an error if the degree is not a power of two or if the step is invalid.
    pub fn rotating_columns(step: i32, degree: u32) -> Result<u32> {
        if !degree.is_power_of_two() {
            return Err(GaloisElementError::InvalidDegree(degree).into());
        }

        let mut positive_step = step.unsigned_abs();
        if positive_step >= (degree >> 1) || positive_step == 0 {
            return Err(GaloisElementError::InvalidRotationStep { step, degree }.into());
        }

        let twice_degree_minus1 = (degree << 1) - 1;
        positive_step &= twice_degree_minus1;

        if step > 0 {
            positive_step = (degree >> 1) - positive_step;
        }

        Ok(GaloisElement::GENERATOR.pow_mod(&(positive_step), &(degree << 1), true))
    }
}

#[cfg(test)]
mod test {
    use eyre::Result;

    use crate::homomorphic_encryption::{
        array_2d::Array2d,
        poly_rq::{
            galois::GaloisElement,
            ntt::{ForwardNtt, InverseNtt},
            poly::PolyRq,
            poly_context::PolyContext,
        },
        scalar::ScalarType,
    };

    fn get_test_poly_with_element3_degree4_moduli1<T: ScalarType + From<u32>>(
    ) -> Result<(PolyRq<T>, PolyRq<T>)> {
        let degree = 4;
        // Convert moduli into the generic type T
        let moduli = vec![T::from(17u32)];
        let plaintext_poly_context = PolyContext::new(degree, &moduli);

        // Convert data and expected_data into type T
        let data =
            Array2d::new(vec![T::from(0u32), T::from(1u32), T::from(2u32), T::from(3u32)], 1, 4);
        let expected_data =
            Array2d::new(vec![T::from(0u32), T::from(3u32), T::from(15u32), T::from(1u32)], 1, 4);

        // Initialize PolyRq with the converted data
        let poly = PolyRq::new(plaintext_poly_context.clone(), data);
        let expected_poly = PolyRq::new(plaintext_poly_context, expected_data);
        Ok((poly, expected_poly))
    }

    fn get_test_poly_with_element3_degree8_moduli1<T: ScalarType + From<u32>>(
    ) -> Result<(PolyRq<T>, PolyRq<T>)> {
        let degree = 8;
        let moduli = vec![T::from(17u32)];
        let plaintext_poly_context = PolyContext::new(degree, &moduli);

        let data = Array2d::new(
            vec![
                T::from(0u32),
                T::from(1u32),
                T::from(2u32),
                T::from(3u32),
                T::from(4u32),
                T::from(5u32),
                T::from(6u32),
                T::from(7u32),
            ],
            1,
            8,
        );
        let expected_data = Array2d::new(
            vec![
                T::from(0u32),
                T::from(14u32),
                T::from(6u32),
                T::from(1u32),
                T::from(13u32),
                T::from(7u32),
                T::from(2u32),
                T::from(12u32),
            ],
            1,
            8,
        );

        let poly = PolyRq::new(plaintext_poly_context.clone(), data);
        let expected_poly = PolyRq::new(plaintext_poly_context, expected_data);
        Ok((poly, expected_poly))
    }

    fn get_test_poly_with_element3_degree8_moduli2<T: ScalarType + From<u32>>(
    ) -> Result<(PolyRq<T>, PolyRq<T>)> {
        let degree = 8;
        let moduli = vec![T::from(17u32), T::from(97u32)];
        let plaintext_poly_context = PolyContext::new(degree, &moduli);

        let data = Array2d::new(
            vec![
                T::from(0u32),
                T::from(1u32),
                T::from(2u32),
                T::from(3u32),
                T::from(4u32),
                T::from(5u32),
                T::from(6u32),
                T::from(7u32),
                T::from(7u32),
                T::from(6u32),
                T::from(5u32),
                T::from(4u32),
                T::from(3u32),
                T::from(2u32),
                T::from(1u32),
                T::from(0u32),
            ],
            2,
            8,
        );
        let expected_data = Array2d::new(
            vec![
                T::from(0u32),
                T::from(14u32),
                T::from(6u32),
                T::from(1u32),
                T::from(13u32),
                T::from(7u32),
                T::from(2u32),
                T::from(12u32),
                T::from(7u32),
                T::from(93u32),
                T::from(1u32),
                T::from(6u32),
                T::from(94u32),
                T::from(0u32),
                T::from(5u32),
                T::from(95u32),
            ],
            2,
            8,
        );

        let poly = PolyRq::new(plaintext_poly_context.clone(), data);
        let expected_poly = PolyRq::new(plaintext_poly_context, expected_data);
        Ok((poly, expected_poly))
    }

    fn apply_galois_test_helper<T: ScalarType>(
        get_func: fn() -> Result<(PolyRq<T>, PolyRq<T>)>,
    ) -> Result<()> {
        let (mut poly, expected_poly) = get_func()?;
        assert_eq!(poly.apply_galois(3), expected_poly);
        assert_eq!(poly.forward_ntt().apply_galois(3).inverse_ntt(), expected_poly);
        for index in 1..poly.degree() {
            let element = index * 2 + 1;
            assert_eq!(
                poly.apply_galois(element).forward_ntt(),
                poly.forward_ntt().apply_galois(element)
            );
        }

        let forward_element = GaloisElement::swapping_rows(poly.degree());
        assert_eq!(poly.apply_galois(forward_element).apply_galois(forward_element), poly);
        assert_eq!(
            poly.forward_ntt().apply_galois(forward_element).apply_galois(forward_element),
            poly.forward_ntt()
        );

        for step in 1..(poly.degree() >> 1) {
            let inverse_step = (poly.degree() >> 1) - step;
            let forward_element = GaloisElement::rotating_columns(step as i32, poly.degree())?;
            let backward_element =
                GaloisElement::rotating_columns(inverse_step as i32, poly.degree())?;
            assert_eq!(poly.apply_galois(forward_element).apply_galois(backward_element), poly);
            assert_eq!(
                poly.forward_ntt().apply_galois(forward_element).apply_galois(backward_element),
                poly.forward_ntt()
            );
        }
        Ok(())
    }

    fn test_apply_galois_for_type<T: ScalarType + From<u32>>() -> Result<()> {
        apply_galois_test_helper(get_test_poly_with_element3_degree4_moduli1::<T>)?;
        apply_galois_test_helper(get_test_poly_with_element3_degree8_moduli1::<T>)?;
        apply_galois_test_helper(get_test_poly_with_element3_degree8_moduli2::<T>)?;
        Ok(())
    }

    #[test]
    pub fn test_apply_galois() -> Result<()> {
        test_apply_galois_for_type::<u32>()?;
        test_apply_galois_for_type::<u64>()?;
        Ok(())
    }
}

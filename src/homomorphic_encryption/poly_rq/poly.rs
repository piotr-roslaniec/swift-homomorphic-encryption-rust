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

use std::ops::{Add, AddAssign, Range, Sub, SubAssign};

use crate::homomorphic_encryption::{
    array_2d::Array2d, poly_rq::poly_context::PolyContext, scalar::ScalarType,
};

/// Represents a polynomial in `R_q = Z_q[X] / (X^N + 1)` for `N` a power of
/// two and `q` a (possibly) multi-word integer.
///
/// The number-theoretic transform is used for efficient arithmetic.
#[derive(Clone, PartialEq, Debug)]
pub struct PolyRq<Type: ScalarType> {
    /// Context for the polynomial.
    pub(crate) context: PolyContext<Type>,
    /// Residue number system (RNS) decomposition of each coefficient.
    ///
    /// Coefficients are stored in coefficient-major order. That is, `data[rns_index, coeff_index]`
    /// stores the `coeff_index`'th coefficient mod `q_{rns_index}.`
    pub data: Array2d<Type>,
}

impl<Type: ScalarType> PolyRq<Type> {
    /// Creates a new polynomial with specified context and data.
    pub fn new(context: PolyContext<Type>, data: Array2d<Type>) -> Self {
        assert_eq!(context.degree, data.column_count as u32);
        assert_eq!(context.moduli.len(), data.row_count);
        assert!(Self::is_valid_data(&context, &data));
        Self { context, data }
    }

    /// Access a single coefficient.
    pub fn get(&self, row: usize, column: usize) -> &Type {
        &self.data[row][column]
    }

    /// Mutably access a single coefficient.
    pub fn set(&mut self, row: usize, column: usize, value: Type) {
        self.data[row][column] = value;
    }

    /// Validate that all coefficients are within the modulus constraints.
    fn is_valid_data(context: &PolyContext<Type>, data: &Array2d<Type>) -> bool {
        for (rns_index, modulus) in context.moduli.iter().enumerate() {
            for coeff in data[rns_index].iter() {
                if *coeff >= *modulus {
                    return false;
                }
            }
        }
        true
    }

    /// Returns the indices of polynomial coefficients.
    pub fn coeff_indices(&self) -> Range<usize> {
        0..self.data.column_count
    }

    /// Returns the indices of RNS moduli.
    pub fn rns_indices(&self) -> Range<usize> {
        0..self.data.row_count
    }

    /// Get all coefficients mod a specific RNS modulus.
    pub fn poly(&self, rns_index: usize) -> &[Type] {
        &self.data[rns_index]
    }

    /// Get a specific coefficient across all moduli.
    pub fn coefficient(&self, coeff_index: usize) -> Vec<Type> {
        self.data.columns_iter().map(|row| *row[coeff_index]).collect::<Vec<_>>()
    }

    /// Initialize a polynomial with all coefficients set to zero.
    pub fn zero(context: PolyContext<Type>) -> Self {
        let zeroes = Array2d::new(
            vec![Type::default(); (context.degree * context.moduli.len() as u32) as usize],
            context.moduli.len(),
            context.degree as usize,
        );
        Self { context, data: zeroes }
    }

    /// Validate that two polynomials have the same context and RNS dimensions.
    fn validate_metadata_equality(&self, other: &Self) {
        assert_eq!(self.context, other.context, "Contexts must match");
        assert_eq!(self.data.row_count, other.data.row_count, "Row counts must match");
        assert_eq!(self.data.column_count, other.data.column_count, "Column counts must match");
    }

    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub fn moduli(&self) -> Vec<Type> {
        self.context.moduli.clone()
    }

    pub fn degree(&self) -> u32 {
        self.context.degree
    }
}

// TODO: What are the proper (restrictive?) bounds for these traits?

impl<Type: ScalarType + std::ops::Rem<Output = Type> + Clone> Add for PolyRq<Type> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = self.clone();
        result += rhs;
        result
    }
}

impl<Type: ScalarType + std::ops::Rem<Output = Type> + Clone> AddAssign for PolyRq<Type> {
    fn add_assign(&mut self, rhs: Self) {
        // Ensure metadata is equal across the two polynomials
        self.validate_metadata_equality(&rhs);

        // Perform modular addition for each coefficient
        for (rns_index, modulus) in self.context.moduli.iter().enumerate() {
            for coeff_index in self.coeff_indices() {
                let lhs_value = self.data[rns_index][coeff_index];
                let rhs_value = rhs.data[rns_index][coeff_index];
                self.data[rns_index][coeff_index] = (lhs_value + rhs_value) % *modulus;
            }
        }
    }
}

impl<Type: ScalarType + std::ops::Rem<Output = Type> + Clone> Sub for PolyRq<Type> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = self.clone();
        result -= rhs;
        result
    }
}

impl<Type: ScalarType + std::ops::Rem<Output = Type> + Clone> SubAssign for PolyRq<Type> {
    fn sub_assign(&mut self, rhs: Self) {
        // Ensure metadata is equal across the two polynomials
        self.validate_metadata_equality(&rhs);

        // Perform modular subtraction for each coefficient
        for (rns_index, modulus) in self.context.moduli.iter().enumerate() {
            for coeff_index in self.coeff_indices() {
                let lhs_value = self.data[rns_index][coeff_index];
                let rhs_value = rhs.data[rns_index][coeff_index];
                self.data[rns_index][coeff_index] = (lhs_value + *modulus - rhs_value) % *modulus;
            }
        }
    }
}

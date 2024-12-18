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

use crate::homomorphic_encryption::array_2d::Array2d;
use crate::homomorphic_encryption::poly_rq::poly_context::PolyContext;
use crate::homomorphic_encryption::scalar::ScalarType;

/// Represents a polynomial in `R_q = Z_q[X] / (X^N + 1)` for `N` a power of
/// two and `q` a (possibly) multi-word integer.
///
/// The number-theoretic transform is used for efficient arithmetic.
#[derive(Clone, PartialEq, Debug)]
pub struct PolyRq<Type: ScalarType> {
    /// Context for the polynomial.
    context: PolyContext<Type>,
    /// Residue number system (RNS) decomposition of each coefficient.
    ///
    /// Coefficients are stored in coefficient-major order. That is, `data[rns_index, coeff_index]` stores the
    /// `coeff_index`'th coefficient mod `q_{rns_index}.`
    pub data: Array2d<Type>,
}

impl<Type: ScalarType> PolyRq<Type> {
    pub fn new(context: PolyContext<Type>, data: Array2d<Type>) -> Self {
        assert_eq!(context.degree, data.column_count);
        assert_eq!(context.moduli.len(), data.row_count as usize);
        assert!(Self::is_valid_data(&data));
        Self { context, data  }
    }

    pub fn get(&self, index: usize) -> &Type {
        &self.data[index]
    }

    pub fn set(&mut self, index: usize, value: Type) {
        self.data[index] = value;
    }

    fn is_valid_data(_data: &Array2d<Type>) -> bool {
        todo!()
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

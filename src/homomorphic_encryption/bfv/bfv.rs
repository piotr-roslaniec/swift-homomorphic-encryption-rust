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

use crate::homomorphic_encryption::ciphertext::Ciphertext;
use crate::homomorphic_encryption::context::Context;
use crate::homomorphic_encryption::he_scheme::{Coeff, EncodeFormat, HeScheme};
use crate::homomorphic_encryption::keys::EvaluationKeyConfiguration;
use crate::homomorphic_encryption::plaintext::Plaintext;
use crate::homomorphic_encryption::scalar::ScalarType;
use eyre::Result;

/// Brakerski-Fan-Vercauteren cryptosystem.
pub struct Bfv<T: ScalarType> {
    _marker: std::marker::PhantomData<T>,
}

/// Protocol for HE schemes.
impl<T: ScalarType> HeScheme for Bfv<T> {
    /// Coefficient type for each polynomial.
    type Scalar = T;
    /// Polynomial format for the `HeScheme::CanonicalCiphertext`.
    type CanonicalCiphertextFormat = Coeff;
    type CoeffPlaintext = Plaintext<Self>;
    type EvalPlaintext = Plaintext<Self>;
    type CoeffCiphertext = Ciphertext<Self>;
    type EvalCiphertext = ();
    type CanonicalCiphertext = ();
    type SecretKey = ();
    type EvaluationKey = ();
    const FRESH_CIPHERTEXT_POLY_COUNT: usize = 0;
    const MIN_NOISE_BUDGET: f64 = 0.0;

    fn generate_secret_key(context: &Context<Self>) -> Result<Self::SecretKey> {
        todo!()
    }

    fn generate_evaluation_key(
        context: &Context<Self>,
        configuration: &EvaluationKeyConfiguration,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::EvaluationKey> {
        todo!()
    }

    fn encode<V>(
        context: &Context<Self>,
        values: &[V],
        format: EncodeFormat,
    ) -> Result<Self::CoeffPlaintext> {
        todo!()
    }

    fn encode_eval<V>(
        context: &Context<Self>,
        values: &[V],
        format: EncodeFormat,
        moduli_count: usize,
    ) -> Result<Self::EvalPlaintext> {
        todo!()
    }

    fn decode<V>(plaintext: &Self::CoeffPlaintext, format: EncodeFormat) -> Result<Vec<V>> {
        todo!()
    }

    fn decode_eval<V>(plaintext: &Self::EvalPlaintext, format: EncodeFormat) -> Result<Vec<V>> {
        todo!()
    }

    fn encrypt(
        plaintext: &Self::CoeffPlaintext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CanonicalCiphertext> {
        todo!()
    }

    fn zero_ciphertext(
        context: &Context<Self>,
        moduli_count: usize,
    ) -> Result<Self::CoeffCiphertext> {
        todo!()
    }

    fn zero_ciphertext_eval(
        context: &Context<Self>,
        moduli_count: usize,
    ) -> Result<Self::EvalCiphertext> {
        todo!()
    }

    fn is_transparent(ciphertext: &Self::CoeffCiphertext) -> bool {
        todo!()
    }

    fn is_transparent_eval(ciphertext: &Self::EvalCiphertext) -> bool {
        todo!()
    }

    fn decrypt(
        ciphertext: &Self::CoeffCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CoeffPlaintext> {
        todo!()
    }

    fn decrypt_eval(
        ciphertext: &Self::EvalCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CoeffPlaintext> {
        todo!()
    }

    fn rotate_columns(
        ciphertext: &mut Self::CanonicalCiphertext,
        step: isize,
        evaluation_key: &Self::EvaluationKey,
    ) -> Result<()> {
        todo!()
    }

    fn swap_rows(
        ciphertext: &mut Self::CanonicalCiphertext,
        evaluation_key: &Self::EvaluationKey,
    ) -> Result<()> {
        todo!()
    }

    fn add_assign_plaintext(
        lhs: &mut Self::CoeffPlaintext,
        rhs: &Self::CoeffPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn add_assign_plaintext_eval(
        lhs: &mut Self::EvalPlaintext,
        rhs: &Self::EvalPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn add_assign(lhs: &mut Self::CoeffCiphertext, rhs: &Self::CoeffCiphertext) -> Result<()> {
        todo!()
    }

    fn add_assign_eval(lhs: &mut Self::EvalCiphertext, rhs: &Self::EvalCiphertext) -> Result<()> {
        todo!()
    }

    fn sub_assign(lhs: &mut Self::CoeffCiphertext, rhs: &Self::CoeffCiphertext) -> Result<()> {
        todo!()
    }

    fn sub_assign_eval(lhs: &mut Self::EvalCiphertext, rhs: &Self::EvalCiphertext) -> Result<()> {
        todo!()
    }

    fn add_assign_ciphertext_plaintext(
        ciphertext: &mut Self::CoeffCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn add_assign_ciphertext_plaintext_eval(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn sub_assign_ciphertext_plaintext(
        ciphertext: &mut Self::CoeffCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn sub_assign_ciphertext_plaintext_eval(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn mul_assign(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn neg_assign(ciphertext: &mut Self::CoeffCiphertext) {
        todo!()
    }

    fn neg_assign_eval(ciphertext: &mut Self::EvalCiphertext) {
        todo!()
    }

    fn inner_product<I>(lhs: I, rhs: I) -> Result<Self::CanonicalCiphertext>
    where
        I: IntoIterator<Item = Self::CanonicalCiphertext>,
    {
        todo!()
    }

    fn inner_product_plaintexts<C, P>(ciphertexts: C, plaintexts: P) -> Result<Self::EvalCiphertext>
    where
        C: IntoIterator<Item = Self::EvalCiphertext>,
        P: IntoIterator<Item = Self::EvalPlaintext>,
    {
        todo!()
    }

    fn inner_product_optional_plaintexts<C, P>(
        ciphertexts: C,
        plaintexts: P,
    ) -> Result<Self::EvalCiphertext>
    where
        C: IntoIterator<Item = Self::EvalCiphertext>,
        P: IntoIterator<Item = Option<Self::EvalPlaintext>>,
    {
        todo!()
    }

    fn mul_assign_ciphertexts(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()> {
        todo!()
    }

    fn add_assign_canonical(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()> {
        todo!()
    }

    fn sub_assign_canonical(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()> {
        todo!()
    }

    fn sub_assign_canonical_plaintext(
        ciphertext: &mut Self::CanonicalCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn sub_assign_canonical_plaintext_eval(
        ciphertext: &mut Self::CanonicalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()> {
        todo!()
    }

    fn mod_switch_down(ciphertext: &mut Self::CanonicalCiphertext) -> Result<()> {
        todo!()
    }

    fn apply_galois(
        ciphertext: &mut Self::CanonicalCiphertext,
        element: usize,
        key: &Self::EvaluationKey,
    ) -> Result<()> {
        todo!()
    }

    fn relinearize(
        ciphertext: &mut Self::CanonicalCiphertext,
        key: &Self::EvaluationKey,
    ) -> Result<()> {
        todo!()
    }

    fn validate_equality(lhs: &Context<Self>, rhs: &Context<Self>) -> Result<()> {
        todo!()
    }

    fn noise_budget(
        ciphertext: &Self::CoeffCiphertext,
        secret_key: &Self::SecretKey,
        variable_time: bool,
    ) -> Result<f64> {
        todo!()
    }

    fn noise_budget_eval(
        ciphertext: &Self::EvalCiphertext,
        secret_key: &Self::SecretKey,
        variable_time: bool,
    ) -> Result<f64> {
        todo!()
    }
}

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

use eyre::Result;

use crate::homomorphic_encryption::{
    context::Context, keys::EvaluationKeyConfiguration, scalar::ScalarType,
};

pub trait PolyFormat: Clone {
    fn description() -> String;
}

#[derive(Clone)]
pub struct Coeff;
impl PolyFormat for Coeff {
    fn description() -> String {
        "Coeff format".to_string()
    }
}

#[derive(Clone)]
pub struct Eval;
impl PolyFormat for Eval {
    fn description() -> String {
        "Eval format".to_string()
    }
}

#[derive(Clone, Copy)]
pub enum EncodeFormat {
    Coefficient,
    Simd,
}

pub trait HeScheme: Sized {
    type Scalar: ScalarType;
    type CanonicalCiphertextFormat: PolyFormat;

    type CoeffPlaintext;
    type EvalPlaintext;
    type CoeffCiphertext;
    type EvalCiphertext;
    type CanonicalCiphertext;
    type SecretKey;
    type EvaluationKey;
    type Context;

    const FRESH_CIPHERTEXT_POLY_COUNT: usize;
    const MIN_NOISE_BUDGET: f64;

    fn generate_secret_key(context: &Context<Self>) -> Result<Self::SecretKey>;

    fn generate_evaluation_key(
        context: &Context<Self>,
        configuration: &EvaluationKeyConfiguration,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::EvaluationKey>;

    fn encode<T: ScalarType>(
        context: &Context<Self>,
        values: &[T],
        format: EncodeFormat,
    ) -> Result<Self::CoeffPlaintext>;

    fn encode_eval<T: ScalarType>(
        context: &Context<Self>,
        values: &[T],
        format: EncodeFormat,
        moduli_count: usize,
    ) -> Result<Self::EvalPlaintext>;

    fn decode<T: ScalarType>(
        plaintext: &Self::CoeffPlaintext,
        format: EncodeFormat,
    ) -> Result<Vec<T>>;

    fn decode_eval<T: ScalarType>(
        plaintext: &Self::EvalPlaintext,
        format: EncodeFormat,
    ) -> Result<Vec<T>>;

    fn encrypt(
        plaintext: &Self::CoeffPlaintext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CanonicalCiphertext>;

    fn zero_ciphertext(
        context: &Context<Self>,
        moduli_count: usize,
    ) -> Result<Self::CoeffCiphertext>;

    fn zero_ciphertext_eval(
        context: &Context<Self>,
        moduli_count: usize,
    ) -> Result<Self::EvalCiphertext>;

    fn is_transparent(ciphertext: &Self::CoeffCiphertext) -> bool;
    fn is_transparent_eval(ciphertext: &Self::EvalCiphertext) -> bool;

    fn decrypt(
        ciphertext: &Self::CoeffCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CoeffPlaintext>;

    fn decrypt_eval(
        ciphertext: &Self::EvalCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::CoeffPlaintext>;

    fn rotate_columns(
        ciphertext: &mut Self::CanonicalCiphertext,
        step: isize,
        evaluation_key: &Self::EvaluationKey,
    ) -> Result<()>;

    fn swap_rows(
        ciphertext: &mut Self::CanonicalCiphertext,
        evaluation_key: &Self::EvaluationKey,
    ) -> Result<()>;

    fn add_assign_plaintext(
        lhs: &mut Self::CoeffPlaintext,
        rhs: &Self::CoeffPlaintext,
    ) -> Result<()>;
    fn add_assign_plaintext_eval(
        lhs: &mut Self::EvalPlaintext,
        rhs: &Self::EvalPlaintext,
    ) -> Result<()>;

    fn add_assign(lhs: &mut Self::CoeffCiphertext, rhs: &Self::CoeffCiphertext) -> Result<()>;
    fn add_assign_eval(lhs: &mut Self::EvalCiphertext, rhs: &Self::EvalCiphertext) -> Result<()>;

    fn sub_assign(lhs: &mut Self::CoeffCiphertext, rhs: &Self::CoeffCiphertext) -> Result<()>;
    fn sub_assign_eval(lhs: &mut Self::EvalCiphertext, rhs: &Self::EvalCiphertext) -> Result<()>;

    fn add_assign_ciphertext_plaintext(
        ciphertext: &mut Self::CoeffCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()>;
    fn add_assign_ciphertext_plaintext_eval(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()>;

    fn sub_assign_ciphertext_plaintext(
        ciphertext: &mut Self::CoeffCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()>;
    fn sub_assign_ciphertext_plaintext_eval(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()>;

    fn mul_assign(
        ciphertext: &mut Self::EvalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()>;

    fn neg_assign(ciphertext: &mut Self::CoeffCiphertext);
    fn neg_assign_eval(ciphertext: &mut Self::EvalCiphertext);

    fn inner_product<I>(lhs: I, rhs: I) -> Result<Self::CanonicalCiphertext>
    where
        I: IntoIterator<Item = Self::CanonicalCiphertext>;

    fn inner_product_plaintexts<C, P>(
        ciphertexts: C,
        plaintexts: P,
    ) -> Result<Self::EvalCiphertext>
    where
        C: IntoIterator<Item = Self::EvalCiphertext>,
        P: IntoIterator<Item = Self::EvalPlaintext>;

    fn inner_product_optional_plaintexts<C, P>(
        ciphertexts: C,
        plaintexts: P,
    ) -> Result<Self::EvalCiphertext>
    where
        C: IntoIterator<Item = Self::EvalCiphertext>,
        P: IntoIterator<Item = Option<Self::EvalPlaintext>>;

    fn mul_assign_ciphertexts(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()>;

    fn add_assign_canonical(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()>;

    fn sub_assign_canonical(
        lhs: &mut Self::CanonicalCiphertext,
        rhs: &Self::CanonicalCiphertext,
    ) -> Result<()>;

    fn sub_assign_canonical_plaintext(
        ciphertext: &mut Self::CanonicalCiphertext,
        plaintext: &Self::CoeffPlaintext,
    ) -> Result<()>;
    fn sub_assign_canonical_plaintext_eval(
        ciphertext: &mut Self::CanonicalCiphertext,
        plaintext: &Self::EvalPlaintext,
    ) -> Result<()>;

    fn mod_switch_down(ciphertext: &mut Self::CanonicalCiphertext) -> Result<()>;

    fn apply_galois(
        ciphertext: &mut Self::CanonicalCiphertext,
        element: usize,
        key: &Self::EvaluationKey,
    ) -> Result<()>;

    /// Converts polynomials from coefficient representation to evaluation representation.
    fn forward_ntt(context: &Self::Context, plaintext: &Self::CoeffPlaintext) -> Result<()>;

    fn relinearize(
        ciphertext: &mut Self::CanonicalCiphertext,
        key: &Self::EvaluationKey,
    ) -> Result<()>;

    fn validate_equality(lhs: &Context<Self>, rhs: &Context<Self>) -> Result<()>;

    fn noise_budget(
        ciphertext: &Self::CoeffCiphertext,
        secret_key: &Self::SecretKey,
        variable_time: bool,
    ) -> Result<f64>;

    fn noise_budget_eval(
        ciphertext: &Self::EvalCiphertext,
        secret_key: &Self::SecretKey,
        variable_time: bool,
    ) -> Result<f64>;
}

impl<S: HeScheme> Context<S> {
    pub fn generate_secret_key(&self) -> Result<S::SecretKey> {
        S::generate_secret_key(self)
    }

    pub fn generate_evaluation_key(
        &self,
        configuration: &EvaluationKeyConfiguration,
        secret_key: &S::SecretKey,
    ) -> Result<S::EvaluationKey> {
        S::generate_evaluation_key(self, configuration, secret_key)
    }
}

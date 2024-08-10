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

use crate::homomorphic_encryption::context::Context;
use crate::homomorphic_encryption::he_scheme::HeScheme;
use crate::homomorphic_encryption::keys::{EvaluationKey, SecretKey};
use crate::private_information_retrieval::cuckoo_table::CuckooTableConfig;
use crate::private_information_retrieval::hash_bucket::HashKeyword;
use crate::private_information_retrieval::index_pir_protocol::{
    IndexPirParameter, ProcessedDatabaseWithParameters, Query, Response,
};
use crate::private_information_retrieval::keyword_database::{
    Keyword, KeywordValue, KeywordValuePair,
};
use eyre::Result;
use std::marker::PhantomData;

/// Configuration for a `KeywordDatabase` in a PIR protocol
pub struct KeywordPirConfig {
    dimension_count: usize,
    cuckoo_table_config: CuckooTableConfig,
    uneven_dimensions: bool,
    pir_parameter: KeywordPirParameter,
}

/// Parameters for a keyword PIR lookup.
///
/// Must be the same between client and server for a correct database lookup.
pub struct KeywordPirParameter {
    /// The number of hash functions in the `CuckooTableConfig`.
    hash_function_count: usize,
}

impl KeywordPirParameter {
    /// Creates a new `KeywordPirParameter` with the given number of hash functions.
    ///
    /// # Parameters
    ///
    /// - `hash_function_count`: The number of hash functions in the `CuckooTableConfig` for the database.
    pub fn new(hash_function_count: usize) -> Self {
        Self { hash_function_count }
    }
}

/// A server that can compute encrypted keyword PIR results.
///
/// The server computes the response to a keyword PIR query by transforming the database to an Index PIR database using
/// cuckoo hashing.
pub struct KeywordPirServer<Scheme: HeScheme> {
    _marker: PhantomData<Scheme>,
}

impl<Scheme: HeScheme> KeywordPirServer<Scheme> {
    pub fn new(
        _context: &Context<Scheme>,
        _processed_database_with_parameters: &ProcessedDatabaseWithParameters<Scheme>,
    ) -> Self {
        todo!()
    }

    pub fn process(
        _database: &[KeywordValuePair],
        _config: &KeywordPirConfig,
        _context: &Context<Scheme>,
    ) -> ProcessedDatabaseWithParameters<Scheme> {
        todo!()
    }

    pub fn compute_response(
        &self,
        _query: &Query<Scheme>,
        _evaluation_key: &EvaluationKey<Scheme>,
    ) -> Result<Response<Scheme>> {
        todo!()
    }
}

/// Client which can perform keyword PIR requests.
pub struct KeywordPirClient<Scheme: HeScheme> {
    keyword_pir_parameter: KeywordPirParameter,
    index_pir_parameter: IndexPirParameter,

    _marker: PhantomData<Scheme>,
}

impl<Scheme: HeScheme> KeywordPirClient<Scheme> {
    /// Creates a new `KeywordPirClient`.
    ///
    /// # Parameters
    ///
    /// - `keyword_pir_parameter`: Parameters for a keyword PIR lookup.
    /// - `index_pir_parameter`: Parameters for an index PIR lookup for the transformed keyword to index database.
    /// - `context`: The context for the HE computations.
    pub fn new(
        _keyword_pir_parameter: &KeywordPirParameter,
        _index_pir_parameter: &IndexPirParameter,
        _context: &Context<Scheme>,
    ) -> Self {
        todo!()
    }

    /// Generates an encrypted `Query` for a keyword PIR lookup.
    ///
    /// # Parameters
    ///
    /// - `keyword`: The keyword whose value to lookup in the database.
    /// - `secret_key`: The `SecretKey` used to encrypt the query.
    ///
    /// # Returns
    ///
    /// An encrypted `Query`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keyword is not found in the database.
    pub fn generate_query(
        &self,
        keyword: &Keyword,
        _secret_key: &SecretKey<Scheme>,
    ) -> Result<Query<Scheme>> {
        let _indices = HashKeyword::hash_indices(
            keyword,
            self.index_pir_parameter.entry_count,
            self.keyword_pir_parameter.hash_function_count,
        )?;
        todo!()
    }

    pub fn decrypt(
        &self,
        _response: &Response<Scheme>,
        _keyword: &Keyword,
        _secret_key: &SecretKey<Scheme>,
    ) -> Result<KeywordValue> {
        todo!()
    }

    /// Generates an `EvaluationKey` for use in server-side PIR computations.
    ///
    /// # Parameters
    ///
    /// - `secret_key`: The `SecretKey`  used to generate the `EvaluationKey`.
    ///
    /// # Returns
    ///
    /// An `EvaluationKey` for use in server-side PIR computations.
    pub fn generate_evaluation_key(
        &self,
        _secret_key: &SecretKey<Scheme>,
    ) -> EvaluationKey<Scheme> {
        todo!()
    }
}

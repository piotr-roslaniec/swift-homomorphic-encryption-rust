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

//! The `keyword_database` module provides an implementation of a sharded keyword-value database
//! with support for Private Information Retrieval (PIR).
//!
//! A keyword database is divided into shards, where each keyword-value pair is assigned to a
//! specific shard based on a hash of the keyword. This sharding approach allows for efficient
//! storage and retrieval of data, especially when combined with PIR techniques.
//!
//! This module provides the following key components:
//!
//! - `KeywordValuePair`: Represents a single keyword-value pair in the database.
//! - `Sharding`: Defines different strategies for dividing the database into shards.
//! - `KeywordDatabaseConfig`: Configuration for the keyword database, including sharding strategy
//!   and PIR configuration.
//! - `KeywordDatabase`: The main data structure implementing the sharded keyword-value database.
//! - `KeywordDatabaseShard`: Represents a single shard in the keyword database.
//! - `ProcessKeywordDatabase`: Utilities for processing the keyword database, including shard
//!   processing and validation.
//! - `Processed`: Represents a processed keyword database ready for PIR queries.
//! - `ShardValidationResult`: Stores the results of validating a processed database shard.
//!
//! The module supports various operations such as:
//!
//! - Creating and configuring a keyword database
//! - Sharding the database based on different strategies
//! - Processing the database for PIR queries
//! - Validating the correctness of database processing
//! - Performing PIR queries on the processed database

use crate::homomorphic_encryption::context::Context;
use crate::homomorphic_encryption::encryption_parameters::EncryptionParameters;
use crate::homomorphic_encryption::he_scheme::HeScheme;
use crate::homomorphic_encryption::keys::{EvaluationKey, EvaluationKeyConfiguration};
use crate::private_information_retrieval::index_pir_protocol::{
    PirAlgorithm, ProcessedDatabaseWithParameters, Query, Response,
};
use crate::private_information_retrieval::keyword_pir_protocol::{
    KeywordPirConfig, KeywordPirServer,
};
use crate::private_information_retrieval::mul_pir::MulPir;
use eyre::Result;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::max;
use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;

/// Keyword database errors.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum KeywordDatabaseError {
    /// Invalid sharding configuration.
    #[error("Invalid sharding configuration")]
    InvalidShardingConfig,

    /// Duplicate keyword in the database.
    #[error("Duplicate keyword in the database: keyword {0}, old value {1}, new value {2}")]
    InvalidDatabaseDuplicateKeyword(String, String, String),

    /// Invalid number of trials per shard. Must be at least 1.
    #[error("Invalid number of trials per shard")]
    InvalidTrialsPerShard,

    /// Missing keyword PIR parameters in a database shard.
    #[error("Missing keyword PIR parameters in a database shard")]
    MissingKeywordPirParametersInShard,

    /// Insufficient noise budget for a PIR response.
    #[error("Insufficient noise budget for a PIR response: {0}")]
    InsufficientNoiseBudget(f64),

    /// Incorrect PIR response.
    #[error("Incorrect PIR response")]
    IncorrectPirResponse,

    /// Empty evaluation key.
    #[error("Empty evaluation key")]
    EmptyEvaluationKey,

    /// Empty query.
    #[error("Empty query")]
    EmptyQuery,
}

impl From<(Keyword, KeywordValue, KeywordValue)> for KeywordDatabaseError {
    fn from(value: (Keyword, KeywordValue, KeywordValue)) -> Self {
        let keyword = String::from_utf8_lossy(value.0.as_slice()).to_string();
        let old_value = String::from_utf8_lossy(value.1.as_slice()).to_string();
        let new_value = String::from_utf8_lossy(value.2.as_slice()).to_string();
        KeywordDatabaseError::InvalidDatabaseDuplicateKeyword(keyword, old_value, new_value)
    }
}

// Declaring types here instead of in KeywordValuePair because associated types are not allowed in structs.
// See: https://github.com/rust-lang/rust/issues/8995

/// Represents a keyword in a keyword-value pair.
pub type Keyword = Vec<u8>;
/// Represents a value in a keyword-value pair.
pub type KeywordValue = Vec<u8>;

/// A keyword with an associated value.
#[derive(Clone)]
pub struct KeywordValuePair {
    keyword: Keyword,
    value: KeywordValue,
}

impl KeywordValuePair {
    /// Creates a new `KeywordValuePair`.
    pub fn new(keyword: Keyword, value: KeywordValue) -> Self {
        Self { keyword, value }
    }

    /// Returns the shard ID for the given shard count.
    ///
    /// # Parameters
    ///
    /// - `shard_count`: The number of shards.
    ///
    /// # Returns
    ///
    /// The shard identifier.
    pub fn shard_id(&self, shard_count: usize) -> String {
        format!("{}", self.shard_index(shard_count))
    }

    /// Returns the shard index for the given shard count.
    ///
    /// # Parameters
    ///
    /// - `shard_count`: The number of shards.
    ///
    /// # Returns
    ///
    /// The shard index.
    pub fn shard_index(&self, shard_count: usize) -> usize {
        let digest = Sha256::digest(&self.keyword);
        let truncated_hash = digest.as_slice()[0..size_of::<u64>()].try_into().unwrap();
        let hash = u64::from_le_bytes(truncated_hash);
        let shard_index = hash % shard_count as u64;
        shard_index as usize
    }
}

/// Different ways to divide database into disjoint shards.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum Sharding {
    /// Divide database into as many shards as neede to average at least `EntryCountPerShard` entries per shard.
    EntryCountPerShard(usize),
    /// Divide database into `ShardCount` approximately equal-sized shards.
    ShardCount(usize),
}

impl FromStr for Sharding {
    type Err = KeywordDatabaseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(KeywordDatabaseError::InvalidShardingConfig);
        }

        // Key names were adapted to match the Swift implementation.
        match parts[0] {
            "entryCountPerShard" => {
                let count = parts[1]
                    .parse::<usize>()
                    .map_err(|_| KeywordDatabaseError::InvalidShardingConfig)?;
                Ok(Sharding::EntryCountPerShard(count))
            },
            "shardCount" => {
                let count = parts[1]
                    .parse::<usize>()
                    .map_err(|_| KeywordDatabaseError::InvalidShardingConfig)?;
                Ok(Sharding::ShardCount(count))
            },
            _ => Err(KeywordDatabaseError::InvalidShardingConfig),
        }
    }
}

impl Display for Sharding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            // Key names were adapted to match the Swift implementation.
            Sharding::EntryCountPerShard(count) => format!("entryCountPerShard:{}", count),
            Sharding::ShardCount(count) => format!("shardCount:{}", count),
        };
        write!(f, "{}", str)
    }
}

impl Sharding {
    /// Returns whether the sharding configuration is valid.
    fn is_valid(&self) -> bool {
        match self {
            Sharding::EntryCountPerShard(count) => *count >= 1,
            Sharding::ShardCount(count) => *count >= 1,
        }
    }

    /// Creates a new `Sharding` from a number of shards.
    ///
    /// # Parameters
    ///
    /// - `shard_count` - Number of shards
    ///
    /// # Errors
    ///
    /// - If `shard_count` is less than 1.
    pub fn new(shard_count: usize) -> Result<Self> {
        let sharding = Sharding::ShardCount(shard_count);
        if sharding.is_valid() {
            Ok(sharding)
        } else {
            Err(KeywordDatabaseError::InvalidShardingConfig.into())
        }
    }

    /// Creates a new `Sharding` from an entry count per shard.
    ///
    /// # Parameters
    ///
    /// - `entry_count_per_shard` - Number of entries per shard
    ///
    /// # Errors
    ///
    /// - If `entry_count_per_shard` is less than 1.
    pub fn from_entry_count_per_shard(entry_count_per_shard: usize) -> Result<Self> {
        let sharding = Sharding::EntryCountPerShard(entry_count_per_shard);
        if sharding.is_valid() {
            Ok(sharding)
        } else {
            Err(KeywordDatabaseError::InvalidShardingConfig.into())
        }
    }

    /// Validates the sharding configuration.
    ///
    /// # Errors
    ///
    /// - If the sharding configuration is invalid.
    // TODO: Do we need both `Sharding::is_valid` and `Sharding::validate`?
    pub fn validate(&self) -> Result<()> {
        if !self.is_valid() {
            Err(KeywordDatabaseError::InvalidShardingConfig.into())
        } else {
            Ok(())
        }
    }
}

/// A shard of `KeywordDatabase`.
pub struct KeywordDatabaseShard {
    /// Identifier for the shard.
    shard_id: String,
    /// Rows in the database.
    rows: Vec<KeywordValuePair>,
}

impl KeywordDatabaseShard {
    /// Returns whether the database has any rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Creates a new `KeywordDatabaseShard`.
    ///
    /// # Parameters
    ///
    /// - `shard_id`: Identifier for the database shard.
    /// - `rows`: Rows in the database.
    pub fn new(shard_id: &str, rows: &[KeywordValuePair]) -> Self {
        Self { shard_id: shard_id.to_string(), rows: rows.to_vec() }
    }
}

/// Configuration for a `KeywordDatabase`.
pub struct KeywordDatabaseConfig {
    /// Sharding configuration.
    pub sharding: Sharding,
    /// Configuration for the keyword PIR protocol.
    pub keyword_pir_config: KeywordPirConfig,
}

impl KeywordDatabaseConfig {
    /// Creates a new `KeywordDatabaseConfig`.
    ///
    /// # Parameters
    ///
    /// - `sharding`: Sharding configuration.
    /// - `keyword_pir_config`: Configuration for the keyword PIR protocol.
    ///
    pub fn new(sharding: Sharding, keyword_pir_config: KeywordPirConfig) -> Self {
        Self { sharding, keyword_pir_config }
    }
}

/// Database of keyword-value pairs, divided into shards.
pub struct KeywordDatabase {
    /// Shards of the database.
    ///
    /// Each keyword-value pair is in exactly one shard.
    shards: HashMap<String, KeywordDatabaseShard>,
}

impl KeywordDatabase {
    /// Creates a `KeywordDatabase`.
    ///
    /// # Parameters
    ///
    /// - `rows`: Keyword-value pairs to store in the database.
    /// - `sharding`: How to shard the database.
    ///
    /// # Errors
    ///
    /// - If we fail to create the database.
    pub fn new(rows: &[KeywordValuePair], sharding: &Sharding) -> Result<Self> {
        let shard_count = match sharding {
            Sharding::EntryCountPerShard(entry_count_per_shard) => {
                // Flooring the division to ensure `entry_count_per_shard` privacy.
                // TODO: Are we sure that this hiding works?
                max(rows.len() / entry_count_per_shard, 1)
            },
            Sharding::ShardCount(shard_count) => *shard_count,
        };

        let mut shards: HashMap<String, KeywordDatabaseShard> = HashMap::new();
        for row in rows {
            let shard_id = row.shard_id(shard_count);
            let shard = shards
                .entry(shard_id.clone())
                .or_insert_with(|| KeywordDatabaseShard::new(&shard_id, &[]));

            if let Some(previous_value) =
                shard.rows.iter().find(|r| r.keyword == row.keyword).map(|x| x.value.clone())
            {
                return Err(KeywordDatabaseError::from((
                    row.keyword.clone(),
                    previous_value,
                    row.value.clone(),
                ))
                .into());
            }

            shard.rows.push(row.clone());
        }

        Ok(Self { shards })
    }
}

/// Arguments for processing a keyword database.
pub struct Arguments<Scheme: HeScheme> {
    /// Configuration for the keyword database.
    database_config: KeywordDatabaseConfig,
    /// Encryption parameters
    encryption_parameters: EncryptionParameters<Scheme>,
    /// PIR algorithm to process with.
    algorithm: PirAlgorithm,
    /// Number of test queries per shard.
    trials_per_shard: usize,
    /// Marker to use the `Scheme` type parameter.
    _marker: PhantomData<Scheme>,
}

impl<Scheme: HeScheme> Arguments<Scheme> {
    /// Creates a new `Arguments` for database processing.
    ///
    /// # Parameters
    ///
    /// - `database_config`: Configuration for the keyword database.
    /// - `encryption_parameters`: Encryption parameters.
    /// - `algorithm`: PIR algorithm to process with.
    /// - `trials_per_shard`: Number of test queries per shard.
    pub fn new(
        database_config: KeywordDatabaseConfig,
        encryption_parameters: EncryptionParameters<Scheme>,
        algorithm: PirAlgorithm,
        trials_per_shard: usize,
    ) -> Self {
        Self {
            database_config,
            encryption_parameters,
            algorithm,
            trials_per_shard,
            _marker: PhantomData,
        }
    }
}

/// Validation results for a single shard.
pub struct ShardValidationResult<Scheme: HeScheme> {
    /// An evaluation key.
    evaluation_key: EvaluationKey<Scheme>,
    /// A query.
    query: Query<Scheme>,
    /// A response.
    response: Response<Scheme>,
    /// Minimum noise budget over all responses.
    noise_budget: f64,
    /// Server runtimes.
    compute_times: Vec<f64>,
}

impl<Scheme: HeScheme> ShardValidationResult<Scheme> {
    /// Creates a new `ShardValidationResult`.
    ///
    /// # Parameters
    ///
    /// - `evaluation_key`: An evaluation key.
    /// - `query`: A query.
    /// - `response`: A response.
    /// - `noise_budget`: Noise budget of the response.
    /// - `compute_times`: Server runtimes.
    pub fn new(
        evaluation_key: EvaluationKey<Scheme>,
        query: Query<Scheme>,
        response: Response<Scheme>,
        noise_budget: f64,
        compute_times: Vec<f64>,
    ) -> Self {
        Self { evaluation_key, query, response, noise_budget, compute_times }
    }
}

/// A processed keyword database.
pub struct Processed<Scheme: HeScheme> {
    /// Evaluation key configuration.
    evaluation_key_config: EvaluationKeyConfiguration,
    /// Maps each shard_id to the associated database shard and PIR parameters.
    shards: HashMap<String, ProcessedDatabaseWithParameters<Scheme>>,
}

impl<Scheme: HeScheme> Processed<Scheme> {
    /// Creates a new `Processed` keyword database.
    ///
    /// # Parameters
    ///
    /// - `evaluation_key_config`: Evaluation key configuration.
    /// - `shards`: Database shards.
    pub fn new(
        evaluation_key_config: EvaluationKeyConfiguration,
        shards: HashMap<String, ProcessedDatabaseWithParameters<Scheme>>,
    ) -> Self {
        Self { evaluation_key_config, shards }
    }
}

/// Utilities for processing a `KeywordDatabase`.
// TODO: Should we turn this into a trait?
pub struct ProcessKeywordDatabase<Scheme> {
    _marker: PhantomData<Scheme>, // TODO: Can we somehow remove this?
}

impl<Scheme: HeScheme> ProcessKeywordDatabase<Scheme> {
    /// Process a database shard.
    ///
    /// # Parameters
    ///
    /// - `shard`: A shard of the keyword database.
    /// - `arguments`: Arguments for processing the database.
    ///
    /// # Returns
    ///
    /// A processed database with parameters.
    ///
    /// # Errors
    ///
    /// - If processing the shard fails.
    pub fn process_shard(
        shard: &KeywordDatabaseShard,
        arguments: &Arguments<Scheme>,
    ) -> Result<ProcessedDatabaseWithParameters<Scheme>> {
        let keyword_pir_config = &arguments.database_config.keyword_pir_config;
        let context = Context::new(&arguments.encryption_parameters);
        let server = KeywordPirServer::process(&shard.rows, keyword_pir_config, &context);
        Ok(server)
    }

    /// Validates the correctness of processing on a shard.
    ///
    /// # Parameters
    ///
    /// - `shard`: Processed database shard.
    /// - `row`: Keyword-value pair to validate in a PIR query.
    /// - `trials` - How many PIR calls to validate. Must be at least 1.
    /// - `context` - Context for the HE computations.
    ///
    /// # Returns
    ///
    /// Validation results for the shard.
    ///
    /// # Errors
    ///
    /// - If validation fails.
    ///
    /// # Note
    ///
    /// See also `ProcessKeywordDatabase::process_shard` to process a shard before validation.
    // pub fn validate_shard(
    //     shard: &ProcessedDatabaseWithParameters<Scheme>,
    //     row: &KeywordValuePair,
    //     trials: usize,
    //     context: &Context<Scheme>,
    // ) -> Result<ShardValidationResult<Scheme>> {
    //     if trials == 0 {
    //         return Err(KeywordDatabaseError::InvalidTrialsPerShard.into());
    //     }
    //
    //     let keyword_pir_parameters = shard
    //         .keyword_pir_parameters
    //         .as_ref()
    //         .ok_or(KeywordDatabaseError::MissingKeywordPirParametersInShard)?;
    //
    //     let server = KeywordPirServer::new(context, shard);
    //     let client = KeywordPirClient::new(keyword_pir_parameters, &shard.pir_parameters, context);
    //
    //     let mut evaluation_key: Option<EvaluationKey<Scheme>> = None;
    //     let mut query: Option<Query<Scheme>> = None;
    //     let mut response = Response::default();
    //     let mut min_noise_budget = f64::INFINITY;
    //
    //     let compute_times: Vec<f64> = (0..trials)
    //         .map(|trial| {
    //             let secret_key = Scheme::generate_secret_key(context)?;
    //             let trial_evaluation_key = client.generate_evaluation_key(&secret_key);
    //             let trial_query = client.generate_query(&row.keyword, &secret_key)?;
    //
    //             let start = Instant::now();
    //             response = server.compute_response(&trial_query, &trial_evaluation_key)?;
    //             let compute_time = start.elapsed().as_secs_f64();
    //
    //             let noise_budget = response.noise_budget(&secret_key, true);
    //             min_noise_budget = min_noise_budget.min(noise_budget);
    //
    //             let decrypted_response = client.decrypt(&response, &row.keyword, &secret_key)?;
    //             if decrypted_response != row.value {
    //                 let noise_budget = response.noise_budget(&secret_key, true);
    //                 if noise_budget < Scheme::MIN_NOISE_BUDGET {
    //                     return Err(KeywordDatabaseError::InsufficientNoiseBudget(noise_budget).into());
    //                 }
    //                 return Err(KeywordDatabaseError::IncorrectPirResponse.into());
    //             }
    //
    //             if trial == 0 {
    //                 evaluation_key = Some(trial_evaluation_key);
    //                 query = Some(trial_query);
    //             }
    //
    //             Ok(compute_time)
    //         })
    //         .collect::<Result<Vec<f64>>>()?;
    //
    //     let evaluation_key = evaluation_key.ok_or(KeywordDatabaseError::EmptyEvaluationKey)?;
    //     let query = query.ok_or(KeywordDatabaseError::EmptyQuery)?;
    //
    //     Ok(ShardValidationResult::new(
    //         evaluation_key,
    //         query,
    //         response,
    //         min_noise_budget,
    //         compute_times,
    //     ))
    // }

    /// Process the database to prepare for PIR queries.
    ///
    /// # Parameters
    ///
    /// - `rows`: Keyword-value pairs to store in the database.
    /// - `arguments`: Arguments for processing the database.
    ///
    /// # Returns
    ///
    /// A processed database.
    ///
    /// # Errors
    ///
    /// - If processing the database fails.
    pub fn process(
        rows: &[KeywordValuePair],
        arguments: Arguments<Scheme>,
    ) -> Result<Processed<Scheme>> {
        let mut evaluation_key_configuration = EvaluationKeyConfiguration::default();
        let keyword_pir_config = &arguments.database_config.keyword_pir_config;

        let context = Context::new(&arguments.encryption_parameters);
        let keyword_database = KeywordDatabase::new(rows, &arguments.database_config.sharding)?;

        let processed_shards: HashMap<String, ProcessedDatabaseWithParameters<Scheme>> =
            keyword_database
                .shards
                .into_iter()
                .filter(|(_, shard)| !shard.is_empty())
                .map(|(shard_id, sharded_database)| {
                    let processed = KeywordPirServer::process(
                        &sharded_database.rows,
                        keyword_pir_config,
                        &context,
                    );
                    evaluation_key_configuration = evaluation_key_configuration.union(
                        MulPir::<Scheme>::evaluation_key_configuration(
                            &processed.pir_parameters,
                            &arguments.encryption_parameters,
                        ),
                    );
                    (shard_id, processed)
                })
                .collect();

        Ok(Processed::new(evaluation_key_configuration, processed_shards))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_information_retrieval::pir_test_utils::get_test_table;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;
    use serde_json;

    #[test]
    fn test_sharding_codable() {
        let shardings = vec![Sharding::ShardCount(10), Sharding::EntryCountPerShard(11)];

        for sharding in shardings {
            let encoded = serde_json::to_string(&sharding).unwrap();
            let decoded: Sharding = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, sharding);
        }
    }

    #[test]
    fn test_sharding() {
        let mut rng = StdRng::seed_from_u64(0);

        let shard_count = 10;
        let row_count = 10;
        let value_size = 3;
        let test_database = get_test_table(row_count, value_size, &mut rng)
            .iter()
            .map(|(k, v)| KeywordValuePair::new(k.clone(), v.clone()))
            .collect::<Vec<_>>();

        let database =
            KeywordDatabase::new(&test_database, &Sharding::ShardCount(shard_count)).unwrap();
        assert!(database.shards.len() <= shard_count);
        assert_eq!(
            database.shards.values().map(|shard| shard.rows.len()).sum::<usize>(),
            row_count
        );

        for row in test_database {
            assert!(database.shards.values().any(|shard| {
                shard.rows.iter().any(|r| r.keyword == row.keyword && r.value == row.value)
            }));
        }
    }

    #[test]
    fn test_sharding_known_answer_test() {
        fn check_keyword_shard(keyword: Keyword, shard_count: usize, expected_shard: usize) {
            assert_eq!(
                KeywordValuePair::new(keyword.clone(), vec![]).shard_index(shard_count),
                expected_shard
            );
        }

        check_keyword_shard(vec![0, 0, 0, 0], 41, 2);
        check_keyword_shard(vec![0, 0, 0, 0], 1001, 635);
        check_keyword_shard(vec![1, 2, 3], 1001, 903);
        check_keyword_shard(vec![3, 2, 1], 1001, 842);
    }
}

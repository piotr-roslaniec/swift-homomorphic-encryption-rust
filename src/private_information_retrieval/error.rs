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

use crate::private_information_retrieval::cuckoo_table::{
    CuckooTableConfigError, CuckooTableError,
};
use crate::private_information_retrieval::hash_bucket::HashBucketError;
use crate::private_information_retrieval::keyword_database::KeywordDatabaseError;
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq)]
pub enum PirError {
    #[error("HashBucketError: {0}")]
    HashBucket(#[from] HashBucketError),

    #[error("CuckooTableConfigError: {0}")]
    CuckooTableConfig(#[from] CuckooTableConfigError),

    #[error("CuckooTableError: {0}")]
    CuckooTable(#[from] CuckooTableError),

    #[error("KeywordDatabaseError: {0}")]
    KeywordDatabase(#[from] KeywordDatabaseError),
}

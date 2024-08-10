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

use std::collections::HashSet;

use rand::Rng;

pub fn generate_random_data<R: Rng>(size: usize, rng: &mut R) -> Vec<u8> {
    (0..size).map(|_| rng.gen()).collect()
}

pub fn get_test_table<R: Rng>(
    row_count: usize,
    value_size: usize,
    rng: &mut R,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let keyword_size = 30;
    let mut keywords = HashSet::new();
    let mut rows = Vec::with_capacity(row_count);

    while rows.len() < row_count {
        let keyword = generate_random_data(keyword_size, rng);
        if keywords.contains(&keyword) {
            continue;
        }
        keywords.insert(keyword.clone());
        let value = generate_random_data(value_size, rng);
        rows.push((keyword, value));
    }

    rows
}

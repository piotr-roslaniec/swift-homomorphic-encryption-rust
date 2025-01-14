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

//! Contains helper methods for constant-time operation on scalars.
// TODO: Currently only needed by CuckooTable

/// Computes `ceil(value / divisor)`.
///
/// # Parameters
/// - `value`: The number we divide.
/// - `divisor`: The number to divide by.
/// - `variable_time`: Must be `true`, indicating this value and `divisor` are leaked through
///   timing.
///
/// # Returns
/// `ceil(value / divisor)`.
///
/// # Warning
/// Leaks this value and `divisor` through timing.
pub fn dividing_ceil(value: i64, divisor: i64, variable_time: bool) -> i64 {
    assert!(variable_time);
    assert_ne!(divisor, 0);
    if value > 0 && divisor > 0 {
        return (value - 1) / divisor + 1;
    }
    if value < 0 && divisor < 0 {
        return (value + 1) / divisor + 1;
    }
    value / divisor
}

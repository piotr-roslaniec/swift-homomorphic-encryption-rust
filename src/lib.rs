//! # Template Rust Library
//!
//! `flowscripter_template_rust_library` provides a sample function to be invoked.

/// Adds two numbers together.
///
/// # Examples
/// ```
/// let arg1 = 2;
/// let arg2 = 2;
/// let answer = flowscripter_template_rust_library::adder(arg1, arg2);
///
/// assert_eq!(4, answer);
/// ```
pub fn adder(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adder_works() {
        assert_eq!(4, adder(2, 2));
    }
}

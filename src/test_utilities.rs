const TEST_POLY_DEGREE: u32 = 16;
const TEST_PLAINTEXT_MODULUS: u32 = 1153;

// pub fn test_coefficient_moduli<T: ScalarType>() -> Result<Vec<T>> {
//     if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u32>() {
//         return T::generate_primes(
//             &[28, 28, 28, 28],
//             false,
//             TEST_POLY_DEGREE
//         );
//     }
//     if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u64>() {
//         return T::generate_primes(
//             &[55, 55, 55, 55],
//             false,
//             TEST_POLY_DEGREE
//         );
//     }
//     eyre::bail!("Unsupported scalar type");
// }

// pub fn get_test_encryption_parameters<Scheme: HeScheme>() -> Result<EncryptionParameters<Scheme>>
// {     let coefficient_moduli = test_coefficient_moduli::<Scheme::Scalar>()?
//         .into_iter()
//         .map(Scheme::Scalar::from)
//         .collect();
//     Ok(EncryptionParameters::new(
//         // TEST_POLY_DEGREE,
//         // Scheme::Scalar::from(TEST_PLAINTEXT_MODULUS),
//         // coefficient_moduli,
//         // ErrorStdDev::StdDev32,
//         // SecurityLevel::Unchecked,
//     ))
// }

// pub fn get_test_context<Scheme: HeScheme>() -> Result<Context<Scheme>> {
//     let encryption_parameters = get_test_encryption_parameters::<Scheme>()?;
//     Ok(Context::new(&encryption_parameters))
// }

use crate::homomorphic_encryption::{poly_rq::poly::PolyRq, scalar::ScalarType};

// TODO: Consider this extension trait pattern for other types

pub trait ForwardNtt<Type: ScalarType> {
    fn forward_ntt(&mut self) -> Self;
}

impl<Type: ScalarType> ForwardNtt<Type> for PolyRq<Type> {
    fn forward_ntt(&mut self) -> Self {
        todo!();
        // for rns_index in self.rns_indices() {
        //     let modulus = &self.context.moduli[rns_index];
        //     let coeffs = &mut self.data[rns_index];
        //     self.context.forward_ntt(coeffs, modulus);
        // }
    }
}

pub trait InverseNtt<Type: ScalarType> {
    fn inverse_ntt(&mut self) -> Self;
}

impl<Type: ScalarType> InverseNtt<Type> for PolyRq<Type> {
    fn inverse_ntt(&mut self) -> Self {
        todo!()
    }
}

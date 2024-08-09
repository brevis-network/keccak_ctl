use anyhow::Result;
use log::Level;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use bincode;

use plonky2_field::extension::Extendable;
use starky_ctl::stark::Stark;

use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_proof::keccak256proof_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::keccak_xor::xor_stark::KeccakXORStark;
use crate::stark_aggregation::aggregation_sponge_permutation;
use crate::verifier_ctl::keccak256verify_stark;
use plonky2::plonk::config::Hasher;
use plonky2::util::timing::TimingTree;

pub fn keccak256<F, C, const D: usize>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let (stark, proof) = keccak256proof_stark::<F, C, D>(msg, hash)?;

    keccak256verify_stark(stark.clone(), proof.clone())?;

    let pfBytes = bincode::serialize(&proof.stark_proofs);
    println!("Proof stark size: {} bytes", pfBytes.unwrap().len());

    let vec: Vec<u8> = vec![104, 101, 108, 108, 111]; // These are bytes for the string "hello"
    let result = String::from_utf8(vec);

    match result {
        Ok(s) => println!("{}", s),
        Err(e) => println!("Failed to convert to String: {}", e),
    }

    let pfBytes2 = bincode::serialize(&proof.stark_proofs);
    let result =  String::from_utf8(pfBytes2.unwrap());
    match result {
        Ok(s) => println!("{}", s),
        Err(e) => println!("Failed to convert to String: {}", e),
    }

    let (data, proof) = aggregation_sponge_permutation::<F, C, D>(&stark, proof)?;
    let timing = TimingTree::new("To verify aggregation", Level::Debug);
    data.verify(proof.clone())?;
    timing.print();

    Ok((data, proof))
}

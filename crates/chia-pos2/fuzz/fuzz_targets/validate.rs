#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chia_pos2::{Bytes32, validate_proof_v2};
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(|data: &[u8]| -> Corpus {
    let mut unstructured = Unstructured::new(data);

    let Ok(plot_id) = Bytes32::arbitrary(&mut unstructured) else {
        return Corpus::Reject;
    };
    let Ok(k_size) = unstructured.int_in_range::<u8>(12..=32) else {
        return Corpus::Reject;
    };
    let Ok(challenge) = Bytes32::arbitrary(&mut unstructured) else {
        return Corpus::Reject;
    };
    let Ok(strength) = unstructured.int_in_range::<u8>(2..=64) else {
        return Corpus::Reject;
    };
    let Ok(proof) = Vec::<u8>::arbitrary(&mut unstructured) else {
        return Corpus::Reject;
    };

    let _ = validate_proof_v2(&plot_id, k_size, &challenge, strength, &proof);
    Corpus::Keep
});

use std::ffi::{CString, c_char};
use std::fs::File;
use std::io::{Error, Read, Result};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

mod bits;

pub const NUM_CHAIN_LINKS: usize = 16;

#[repr(C)]
#[derive(Default, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// This object contains a quality proof along with metadata required to look
/// up the remaining proof fragments from the plot, to form a partial proof
pub struct QualityChain {
    pub chain_links: [u64; NUM_CHAIN_LINKS],
}

unsafe extern "C" {
    // these C functions are defined in src/api.cpp

    fn validate_proof(
        plot_id: *const u8,
        k_size: u8,
        strength: u8,
        challenge: *const u8,
        proof: *const u32,
        testnet: u8,
        quality: *mut QualityChain,
    ) -> bool;

    fn qualities_for_challenge(
        plot_file: *const c_char,
        challenge: *const u8,
        output: *mut QualityChain,
        num_outputs: u32,
    ) -> u32;

    // proof must point to exactly 16 proof fragments (each a uint64_t)
    // plot ID must point to exactly 32 bytes
    // output must point to exactly 512 32 bit integers
    fn solve_partial_proof(
        quality: *const QualityChain,
        plot_id: *const u8,
        k: u8,
        strength: u8,
        testnet: u8,
        output: *mut u32,
    ) -> bool;

    // Converts full proof to quality string (does not validate).
    // plot_id must point to 32 bytes
    // proof to TOTAL_XS_IN_PROOF (128) uint32_t
    // quality is output
    fn proof_to_quality_string(
        plot_id: *const u8,
        k: u8,
        strength: u8,
        proof: *const u32,
        testnet: u8,
        quality: *mut QualityChain,
    ) -> bool;

    fn create_plot(
        filename: *const c_char,
        k: u8,
        strength: u8,
        plot_id: *const u8,
        index: u16,
        meta_group: u8,
        memo: *const u8,
        memo_length: u8,
        testnet: u8,
    ) -> bool;
}

pub type Bytes32 = [u8; 32];

/// `testnet` must match the network used to create the plot and to validate proofs.
pub fn solve_proof(
    quality_proof: &QualityChain,
    plot_id: &Bytes32,
    k: u8,
    strength: u8,
    testnet: bool,
) -> Vec<u8> {
    let mut proof = [0_u32; 128];
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // proof must point to exactly 128 x-values (each a uint32_t)
    // plot ID must point to exactly 32 bytes
    // output must point to exactly 512 32-bit integers
    if !unsafe {
        solve_partial_proof(
            quality_proof,
            plot_id.as_ptr(),
            k,
            strength,
            u8::from(testnet),
            proof.as_mut_ptr(),
        )
    } {
        return vec![];
    }

    bits::compact_bits(&proof, k)
}

/// `testnet`: use `true` for testnet plot parameters, `false` for mainnet.
pub fn validate_proof_v2(
    plot_id: &Bytes32,
    size: u8,
    challenge: &Bytes32,
    strength: u8,
    proof: &[u8],
    testnet: bool,
) -> Option<QualityChain> {
    let x_values = bits::expand_bits(proof, size)?;

    if x_values.len() != NUM_CHAIN_LINKS * 8 {
        // a full proof has exactly 128 x-values. This is invalid or incomplete
        return None;
    }

    let mut quality = QualityChain::default();
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // plot_id must point to 32 bytes
    // challenge must point to 32 bytes
    // proof must point to 512 uint32_t
    let valid = unsafe {
        validate_proof(
            plot_id.as_ptr(),
            size,
            strength,
            challenge.as_ptr(),
            x_values.as_ptr(),
            u8::from(testnet),
            &mut quality,
        )
    };
    if valid { Some(quality) } else { None }
}

/// Converts full proof bytes to quality string (does not validate the proof).
/// Returns `Some(quality)` on success, `None` if proof format is invalid or conversion fails.
/// `testnet` must match the network used when the proof was produced.
pub fn quality_string_from_proof(
    plot_id: &Bytes32,
    k: u8,
    strength: u8,
    proof: &[u8],
    testnet: bool,
) -> Option<QualityChain> {
    let x_values = bits::expand_bits(proof, k)?;

    if x_values.len() != NUM_CHAIN_LINKS * 8 {
        return None;
    }

    let mut quality = QualityChain::default();
    // SAFETY: plot_id 32 bytes, proof 128 u32s, quality is output. See src/api.cpp.
    let ok = unsafe {
        // Call the C API (extern declared above); avoid name shadowing via alias.
        proof_to_quality_string(
            plot_id.as_ptr(),
            k,
            strength,
            x_values.as_ptr(),
            u8::from(testnet),
            &mut quality,
        )
    };
    if ok { Some(quality) } else { None }
}

/// `testnet`: use `true` to create a plot with testnet parameters (not valid on mainnet).
#[allow(clippy::too_many_arguments)]
pub fn create_v2_plot(
    filename: &Path,
    k: u8,
    strength: u8,
    plot_id: &Bytes32,
    index: u16,
    meta_group: u8,
    memo: &[u8],
    testnet: bool,
) -> Result<()> {
    let Some(filename) = filename.to_str() else {
        return Err(Error::other("invalid path"));
    };

    if memo.len() > 255 {
        return Err(Error::other("invalid memo"));
    };

    let filename = CString::new(filename)?;
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // filename is the full path, null terminated
    // plot_id must point to 32 bytes of plot ID
    // memo must point to bytes containing:
    // * pool contract puzzle hash or pool public key
    // * farmer public key
    // * plot secret key
    // returns true on success
    let success: bool = unsafe {
        create_plot(
            filename.as_ptr(),
            k,
            strength,
            plot_id.as_ptr(),
            index,
            meta_group,
            memo.as_ptr(),
            memo.len() as u8,
            u8::from(testnet),
        )
    };
    if success {
        Ok(())
    } else {
        Err(Error::other("failed to create plot file"))
    }
}

/// out must point to exactly 129 bytes
/// serializes the QualityProof into the form that will be hashed together with
/// the challenge to determine the quality of ths proof. The quality is used to
/// check if it passes the current difficulty. The format is:
/// 1 byte: plot strength
/// repeat 16 times:
///   8 bytes: little-endian proof fragment
pub fn serialize_quality(
    fragments: &[u64; NUM_CHAIN_LINKS],
    strength: u8,
) -> [u8; NUM_CHAIN_LINKS * 8 + 1] {
    let mut ret = [0_u8; 129];

    ret[0] = strength;
    let mut idx = 1;
    for cl in fragments {
        ret[idx..(idx + 8)].clone_from_slice(&cl.to_le_bytes());
        idx += 8;
    }
    ret
}

/// Farmer wide state for prover
#[derive(Serialize, Deserialize)]
pub struct Prover {
    path: PathBuf,
    plot_id: Bytes32,
    memo: Vec<u8>,
    strength: u8,
    index: u16,
    meta_group: u8,
    size: u8,
}

impl Prover {
    pub fn new(plot_path: &Path) -> Result<Prover> {
        let mut file = File::open(plot_path)?;

        // Read PlotData from a binary file. The v2 plot header format is as
        // follows:
        // 4 bytes:  "pos2"
        // 1 byte:   version. 0=invalid, 1=fat plots, 2=benesh plots (compressed)
        // 32 bytes: plot ID
        // 1 byte:   k-size
        // 1 byte:   strength, defaults to 2
        // 2 bytes:  index
        // 1 byte:   meta group
        // 1 byte:   memo length (either 112 or 128)
        // varies:   memo
        let mut header = [0_u8; 4 + 1 + 32 + 1 + 1 + 1 + 2 + 1 + 128];
        file.read_exact(&mut header)?;

        let mut offset: usize = 0;
        if &header[offset..(offset + 4)] != b"pos2" {
            return Err(Error::other("Not a plotfile"));
        }
        offset += 4;
        if header[offset] != 1 {
            return Err(Error::other("unsupported plot version"));
        }
        offset += 1;
        let plot_id: [u8; 32] = header[offset..(offset + 32)].try_into().unwrap();
        offset += 32;
        let size = header[offset];
        if !(18..=32).contains(&size) || (size % 2) != 0 {
            return Err(Error::other("invalid k-size"));
        }
        offset += 1;

        let strength = header[offset];
        if strength < 2 {
            return Err(Error::other("invalid strength"));
        }
        offset += 1;

        let index = u16::from_le_bytes(header[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let meta_group = header[offset];
        offset += 1;

        let memo_len = header[offset];
        offset += 1;

        let memo: &[u8] = &header[offset..(offset + memo_len as usize)];

        Ok(Prover {
            path: plot_path.to_path_buf(),
            plot_id,
            memo: memo.to_vec(),
            strength,
            index,
            meta_group,
            size,
        })
    }

    pub fn get_qualities_for_challenge(&self, challenge: &Bytes32) -> Result<Vec<QualityChain>> {
        let Some(plot_path) = self.path.to_str() else {
            return Err(Error::other("invalid path"));
        };

        let plot_path = CString::new(plot_path)?;

        let mut results = Vec::<QualityChain>::with_capacity(10);
        // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
        // find quality proofs for a challenge.
        // challenge must point to 32 bytes
        // plot_file must be a null-terminated string
        // output must point to "num_outputs" objects
        unsafe {
            let num_results = qualities_for_challenge(
                plot_path.as_ptr(),
                challenge.as_ptr(),
                results.as_mut_ptr(),
                10,
            );
            results.set_len(num_results as usize);
        }
        Ok(results)
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn plot_id(&self) -> &Bytes32 {
        &self.plot_id
    }

    pub fn get_strength(&self) -> u8 {
        self.strength
    }

    pub fn get_filename(&self) -> String {
        // This conversion should be safe because the path is constructed from a
        // string
        self.path.to_string_lossy().into_owned()
    }

    pub fn get_memo(&self) -> &[u8] {
        &self.memo
    }

    pub fn get_meta_group(&self) -> u8 {
        self.meta_group
    }

    pub fn get_plot_index(&self) -> u16 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Creates a v2 plot if missing, runs 100 challenges, solves proofs, validates,
    /// and round-trips proof -> quality_string and checks it matches the original quality.
    /// Matrix: 2×2×2 (testnet × plot index × meta group) = 8 cases.
    /// Expected proof totals are defined in `expected_proof_count` below; update them if the
    /// challenge loop range or plot parameters change.
    #[rstest]
    /// This test is expensive to run in un-optimized mode. To run this test:
    /// cargo test --release -- --include-ignored
    #[ignore]
    fn test_plot_roundtrip(
        #[values(false, true)] testnet: bool,
        #[values(0u16, 3u16)] index: u16,
        #[values(0u8, 7u8)] meta_group: u8,
    ) {
        let k = 20u8;
        let strength = 2u8;
        let mut plot_id = [0xabu8; 32];
        plot_id[0..2].copy_from_slice(&index.to_le_bytes());
        plot_id[2] = meta_group;

        let memo = [0u8; 112];
        let plot_name = format!(
            "pos2_chia_test_k20_i{index}_g{meta_group}{}.plot",
            if testnet { "_testnet" } else { "" }
        );
        let plot_path = std::env::temp_dir().join(plot_name);

        if !plot_path.exists() {
            create_v2_plot(
                &plot_path, k, strength, &plot_id, index, meta_group, &memo, testnet,
            )
            .expect("create_v2_plot");
        }

        let prover = Prover::new(&plot_path).expect("open prover");
        assert_eq!(prover.size(), k);
        assert_eq!(prover.get_strength(), strength);
        assert_eq!(prover.get_plot_index(), index);
        assert_eq!(prover.get_meta_group(), meta_group);
        let plot_id = *prover.plot_id();

        let mut num_proofs = 0;
        let mut challenge = [0u8; 32];
        for challenge_idx in 0..100u32 {
            challenge[0..4].copy_from_slice(&challenge_idx.to_le_bytes());

            let qualities = prover
                .get_qualities_for_challenge(&challenge)
                .expect("get_qualities_for_challenge");

            for quality in qualities {
                let proof = solve_proof(&quality, &plot_id, k, strength, testnet);
                assert!(!proof.is_empty(), "failed to solve proof");
                num_proofs += 1;
                assert!(
                    validate_proof_v2(&plot_id, k, &challenge, strength, &proof, testnet).is_some(),
                    "proof should validate for challenge {challenge_idx} (testnet={testnet} index={index} meta_group={meta_group})",
                );
                assert!(
                    validate_proof_v2(&plot_id, k, &challenge, strength, &proof, !testnet)
                        .is_none(),
                    "proof must not validate under opposite network flag (challenge {challenge_idx}, testnet={testnet})",
                );
                let recovered = quality_string_from_proof(&plot_id, k, strength, &proof, testnet);
                let recovered = recovered.expect("quality_string_from_proof");
                assert_eq!(
                    quality.chain_links, recovered.chain_links,
                    "challenge {challenge_idx}: quality roundtrip must match",
                );
            }
        }
        let expected = expected_proof_count(testnet, index, meta_group);
        assert_eq!(
            num_proofs, expected,
            "testnet={testnet} index={index} meta_group={meta_group}",
        );
    }

    /// Expected number of qualities (proofs) found over 100 challenges for each test matrix case.
    /// Tallies over **100** sequential challenges (`challenge_idx` 0..100).
    fn expected_proof_count(testnet: bool, index: u16, meta_group: u8) -> u32 {
        match (testnet, index, meta_group) {
            (false, 0, 0) => 90,
            (false, 0, 7) => 77,
            (false, 3, 0) => 99,
            (false, 3, 7) => 99,
            (true, 0, 0) => 74,
            (true, 0, 7) => 113,
            (true, 3, 0) => 72,
            (true, 3, 7) => 62,
            _ => unreachable!("test matrix is fixed to 8 cases"),
        }
    }

    #[rstest]
    fn test_serialize_quality(
        #[values(1, 0xff00, 0x777777)] step_size: u64,
        #[values(0, 0xffffffff00000000, 0xff00ff00ff00ff00)] fragment_start: u64,
        #[values(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 23, 26, 28, 33, 63, 64, 100, 200, 240, 255
        )]
        strength: u8,
    ) {
        let mut quality = QualityChain::default();

        let mut idx = fragment_start;
        for link in &mut quality.chain_links {
            *link = idx;
            idx += step_size;
        }

        let quality_str = serialize_quality(&quality.chain_links, strength);
        assert_eq!(quality_str[0], strength);
        idx = fragment_start;
        for i in (1..(NUM_CHAIN_LINKS * 8 + 1)).step_by(8) {
            assert_eq!(
                u64::from_le_bytes(quality_str[i..(i + 8)].try_into().unwrap()),
                idx
            );
            idx += step_size;
        }
    }
}

use std::ffi::{CString, c_char};
use std::io::{Error, Result};
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

/// This object ties a quality chain to a plot index.
/// This must reflect the struct by the same name in the C++ side.
#[repr(C)]
#[derive(Default, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlotQualityChain {
    pub chain: QualityChain,
    pub plot_index: u16,
}

// Corresponds to PlotGroupFile::Info
#[repr(C)]
#[derive(Default, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlotGroupInfo {
    chunks_pos: u64,
    chunk_index_offset: u64,
    chunk_index_compressed_size: u64,
    plot_group_id: [u8; 32],
    group_size: u16,
    version: u8,
    k: u8,
    strength: u8,
    meta_group: u8,
    memo_length: u8,
}

unsafe extern "C" {
    // these C functions are defined in src/api.cpp

    fn validate_proof(
        plot_group_id: *const u8,
        plot_index: u16,
        k_size: u8,
        strength: u8,
        meta_group: u8,
        challenge: *const u8,
        proof: *const u32,
        quality: *mut QualityChain,
    ) -> bool;

    fn qualities_for_challenge(
        plot_group_file: *const c_char,
        challenge: *const u8,
        output: *mut PlotQualityChain,
        in_out_max_outputs: *mut u32,
        plot_index_base: u16,
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
        quality: *mut QualityChain,
    ) -> bool;

    // proof must point to exactly 16 proof fragments (each a uint64_t)
    // plot ID must point to exactly 32 bytes
    // output must point to exactly 512 32 bit integers
    fn solve_partial_proof(
        quality: *const QualityChain,
        plot_id: *const u8,
        k: u8,
        strength: u8,
        output: *mut u32,
    ) -> bool;

    fn create_single_plot_group(
        filename: *const c_char,
        k: u8,
        strength: u8,
        plot_group_id: *const u8,
        index: u16,
        meta_group: u8,
        memo: *const u8,
        memo_length: u8,
    ) -> bool;

    fn derive_plot_id(
        out_plot_id: *mut u8,
        plot_group_id: *const u8,
        plot_index: u16,
        meta_group: u8,
    ) -> bool;

    fn plot_group_read_info(
        out_info: *mut PlotGroupInfo,
        memo_buf: *mut u8,
        memo_buf_size: *mut u8,
        plot_group_path: *const c_char,
    ) -> bool;
}

pub type Bytes32 = [u8; 32];

pub fn solve_proof(
    quality_proof: &QualityChain,
    plot_id: &Bytes32,
    k: u8,
    strength: u8,
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
            proof.as_mut_ptr(),
        )
    } {
        return vec![];
    }

    bits::compact_bits(&proof, k)
}

pub fn validate_proof_v2(
    plot_group_id: &Bytes32,
    plot_index: u16,
    size: u8,
    strength: u8,
    meta_group: u8,
    challenge: &Bytes32,
    proof: &[u8],
) -> Option<QualityChain> {
    let x_values = bits::expand_bits(proof, size)?;

    if x_values.len() != NUM_CHAIN_LINKS * 8 {
        // a full proof has exactly 128 x-values. This is invalid or incomplete
        return None;
    }

    let mut quality = QualityChain::default();
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // plot_group_id must point to 32 bytes
    // challenge must point to 32 bytes
    // proof must point to 512 uint32_t
    let valid = unsafe {
        validate_proof(
            plot_group_id.as_ptr(),
            plot_index,
            size,
            strength,
            meta_group,
            challenge.as_ptr(),
            x_values.as_ptr(),
            &mut quality,
        )
    };
    if valid { Some(quality) } else { None }
}

/// Converts full proof bytes to quality string (does not validate the proof).
/// Returns `Some(quality)` on success, `None` if proof format is invalid or conversion fails.
pub fn quality_string_from_proof(
    plot_id: &Bytes32,
    k: u8,
    strength: u8,
    proof: &[u8],
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
            &mut quality,
        )
    };
    if ok { Some(quality) } else { None }
}

#[allow(clippy::too_many_arguments)]
pub fn create_v2_single_plot_group(
    filename: &Path,
    k: u8,
    strength: u8,
    plot_group_id: &Bytes32,
    index: u16,
    meta_group: u8,
    memo: &[u8],
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
    // plot_group_id must point to 32 bytes of plot group ID
    // memo must point to bytes containing:
    // * pool contract puzzle hash or pool public key
    // * farmer public key
    // * plot secret key
    // returns true on success
    let success: bool = unsafe {
        create_single_plot_group(
            filename.as_ptr(),
            k,
            strength,
            plot_group_id.as_ptr(),
            index,
            meta_group,
            memo.as_ptr(),
            memo.len() as u8,
        )
    };
    if success {
        Ok(())
    } else {
        Err(Error::other("failed to create plot file"))
    }
}

pub fn plot_id_for_index(
    plot_group_id: &Bytes32,
    plot_index: u16,
    meta_group: u8,
) -> Option<Bytes32> {
    let mut plot_id: Bytes32 = [0; 32];

    let valid = unsafe {
        derive_plot_id(
            plot_id.as_mut_ptr(),
            plot_group_id.as_ptr(),
            plot_index,
            meta_group,
        )
    };

    if valid { Some(plot_id) } else { None }
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
    plot_group_id: Bytes32,
    memo: Vec<u8>,
    group_size: u16,
    strength: u8,
    meta_group: u8,
    size: u8,
}

impl Prover {
    pub fn new(plot_group_path: &Path) -> Result<Prover> {
        let mut info = PlotGroupInfo::default();
        let mut memo_buf = [0u8; 255];

        let c_path = CString::new(plot_group_path.to_string_lossy().as_bytes()).unwrap();

        let mut memo_len = memo_buf.len() as u8;
        let result = unsafe {
            plot_group_read_info(
                &mut info,
                memo_buf.as_mut_ptr(),
                &mut memo_len,
                c_path.as_ptr(),
            )
        };

        if !result {
            return Err(Error::other("Failed to get PlotGroupFile info"));
        }

        Ok(Prover {
            path: plot_group_path.to_path_buf(),
            plot_group_id: info.plot_group_id,
            memo: memo_buf[..memo_len as usize].to_vec(),
            group_size: info.group_size,
            strength: info.strength,
            meta_group: info.meta_group,
            size: info.k,
        })
    }

    pub fn get_qualities_for_challenge(
        &self,
        challenge: &Bytes32,
    ) -> Result<Vec<PlotQualityChain>> {
        self.get_qualities_for_challenge_with_base_index(challenge, 0)
    }

    fn get_qualities_for_challenge_with_base_index(
        &self,
        challenge: &Bytes32,
        plot_index_base: u16,
    ) -> Result<Vec<PlotQualityChain>> {
        #[cfg(not(test))]
        {
            if plot_index_base != 0 {
                return Err(Error::other("unexpected non-zero plot index base"));
            }
        }

        let Some(plot_path) = self.path.to_str() else {
            return Err(Error::other("invalid path"));
        };

        let plot_path = CString::new(plot_path)?;

        // Better safe than sorry (hitting the disk twice), reserve enough space to ensure all proofs fit.
        let cap = std::cmp::max(16, self.group_size as usize * 5);
        let mut results = Vec::<PlotQualityChain>::with_capacity(cap);

        let mut num_results = results.capacity() as u32;

        // We look at most twice so that if our results buffer is not big enough
        // for the number of proofs obtained, then we resize it to the required
        // size on the second pass.
        for i in 0..2 {
            // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
            // find quality proofs for a challenge.
            // challenge must point to 32 bytes
            // plot_file must be a null-terminated string
            // output must point to "num_outputs" objects
            unsafe {
                let ok = qualities_for_challenge(
                    plot_path.as_ptr(),
                    challenge.as_ptr(),
                    results.as_mut_ptr(),
                    &mut num_results,
                    plot_index_base,
                );

                if !ok {
                    return Err(Error::other("qualities_for_challenge() failed"));
                }

                if num_results as usize <= results.capacity() {
                    results.set_len(num_results as usize);
                    break;
                }

                // Need to resize and try again
                if i == 0 {
                    assert!(num_results as usize > results.capacity());
                    results.reserve(num_results as usize);
                    num_results = results.capacity() as u32;
                } else {
                    // If somehow we ended up num_results gave us MORE on the second run
                    // (which should never happen), then cap the results.
                    let result_len = std::cmp::min(num_results as usize, results.capacity());
                    results.set_len(result_len);
                }
            }
        }

        Ok(results)
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn plot_group_id(&self) -> &Bytes32 {
        &self.plot_group_id
    }

    pub fn plot_id_for_index(&self, plot_index: u16) -> Bytes32 {
        let mut plot_id = Bytes32::default();
        unsafe {
            derive_plot_id(
                plot_id.as_mut_ptr(),
                self.plot_group_id.as_ptr(),
                plot_index,
                self.meta_group,
            );
        }

        plot_id
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

    pub fn get_group_size(&self) -> u16 {
        self.group_size
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use rstest::rstest;

    /// Creates a v2 plot if missing, runs 100 challenges, solves proofs, validates,
    /// and round-trips proof -> quality_string and checks it matches the original quality.
    /// Matrix: 2×2 (plot index × meta group) = 4 cases.
    /// Expected proof totals are defined in `expected_proof_count` below; update them if the
    /// challenge loop range or plot parameters change.
    #[rstest]
    /// This test is expensive to run in un-optimized mode. To run this test:
    /// cargo test --release -- --include-ignored
    #[ignore]
    fn test_plot_roundtrip(#[values(0u16, 3u16)] index: u16, #[values(0u8, 7u8)] meta_group: u8) {
        let k = 20u8;
        let strength = 2u8;
        let mut plot_group_id = [0xabu8; 32];
        plot_group_id[0..2].copy_from_slice(&index.to_le_bytes());
        plot_group_id[2] = meta_group;

        let memo = [0u8; 112];
        let plot_name = format!("pos2_chia_test_k20_i{index}_m{meta_group}.gplot",);
        let plot_dir = std::env::current_dir().unwrap().join(".test_plots");
        std::fs::create_dir_all(&plot_dir).unwrap();
        let plot_path = plot_dir.join(plot_name);

        if !plot_path.exists() {
            create_v2_single_plot_group(
                &plot_path,
                k,
                strength,
                &plot_group_id,
                index,
                meta_group,
                &memo,
            )
            .expect("create_v2_plot");
        }

        let prover = Prover::new(&plot_path).expect("open prover");
        assert_eq!(prover.size(), k);
        assert_eq!(prover.get_strength(), strength);
        assert_eq!(prover.get_meta_group(), meta_group);

        let plot_id = prover.plot_id_for_index(index);

        let mut num_proofs = 0;
        let mut challenge = [0u8; 32];
        for challenge_idx in 0..100u32 {
            challenge[0..4].copy_from_slice(&challenge_idx.to_le_bytes());

            let qualities = prover
                .get_qualities_for_challenge_with_base_index(&challenge, index)
                .expect("get_qualities_for_challenge");

            for quality in qualities {
                assert_eq!(index, quality.plot_index);

                let proof = solve_proof(&quality.chain, &plot_id, k, strength);
                assert!(!proof.is_empty(), "failed to solve proof");
                num_proofs += 1;
                assert!(
                    validate_proof_v2(
                        &plot_group_id,
                        index,
                        k,
                        strength,
                        meta_group,
                        &challenge,
                        &proof
                    )
                    .is_some(),
                    "proof should validate for challenge {challenge_idx} (index={index} meta_group={meta_group})",
                );

                let recovered = quality_string_from_proof(&plot_id, k, strength, &proof);
                let recovered = recovered.expect("quality_string_from_proof");
                assert_eq!(
                    quality.chain.chain_links, recovered.chain_links,
                    "challenge {challenge_idx}: quality roundtrip must match",
                );
            }
        }
        let expected = expected_proof_count(index, meta_group);
        assert_eq!(
            num_proofs, expected,
            "index={index} meta_group={meta_group}",
        );
    }

    /// Expected number of qualities (proofs) found over 100 challenges for each test matrix case.
    /// Tallies over **100** sequential challenges (`challenge_idx` 0..100).
    fn expected_proof_count(index: u16, meta_group: u8) -> u32 {
        match (index, meta_group) {
            (0, 0) => 97,
            (0, 7) => 92,
            (3, 0) => 111,
            (3, 7) => 122,
            _ => unreachable!("test matrix is fixed to 4 cases"),
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

    /// Creates a deterministic k=18 plot (cached in temp) and checks a hard-coded
    /// challenge known to make `get_qualities_for_challenge()` return duplicate
    /// quality chains today.
    ///
    /// Found by scanning LE `challenge_idx` values against this plot; challenge
    /// `5775` returns 2 qualities with only 1 unique chain.
    ///
    /// Asserts the intended invariant (no duplicates). Fails until the
    /// prover/chainer deduplicates results.
    #[test]
    fn test_no_duplicate_qualities_for_known_challenge() {
        let k = 18u8;
        let strength = 2u8;
        let index = 0u16;
        let meta_group = 0u8;
        let plot_id = [0x12u8; 32];
        let memo = [0u8; 112];
        let plot_path = std::env::current_dir()
            .unwrap()
            .join("pos2_dup_qualities_k18.gplot");
        if !plot_path.exists() {
            create_v2_single_plot_group(
                &plot_path, k, strength, &plot_id, index, meta_group, &memo,
            )
            .expect("create_v2_plot");
        }

        let prover = Prover::new(&plot_path).expect("open prover");
        assert_eq!(prover.size(), k);
        assert_eq!(prover.get_strength(), strength);

        // Deterministic challenge that currently yields duplicate quality chains.
        const CHALLENGE_IDX: i32 = 15_849;

        let mut challenge = [0u8; 32];
        challenge[0..4].copy_from_slice(&CHALLENGE_IDX.to_le_bytes());

        let qualities = prover
            .get_qualities_for_challenge(&challenge)
            .expect("get_qualities_for_challenge");

        assert!(
            !qualities.is_empty(),
            "challenge_idx={CHALLENGE_IDX}: expected at least one quality",
        );

        let mut uniq = HashSet::<[u64; NUM_CHAIN_LINKS]>::with_capacity(qualities.len());
        for q in &qualities {
            assert!(
                uniq.insert(q.chain.chain_links),
                "duplicate qualities returned by get_qualities_for_challenge() \
                    (challenge_idx={CHALLENGE_IDX} count={} unique_so_far={})",
                qualities.len(),
                uniq.len(),
            );
        }
    }
}

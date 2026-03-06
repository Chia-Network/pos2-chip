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
    plot_id: &Bytes32,
    size: u8,
    challenge: &Bytes32,
    strength: u8,
    proof: &[u8],
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

pub fn create_v2_plot(
    filename: &Path,
    k: u8,
    strength: u8,
    plot_id: &Bytes32,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Creates a v2 plot if missing, runs 100 challenges, solves proofs, validates,
    /// and round-trips proof -> quality_string and checks it matches the original quality.
    #[test]
    fn test_plot_roundtrip() {
        let k = 20u8;
        let strength = 2u8;
        let index = 0u16;
        let meta_group = 0u8;
        let plot_id: Bytes32 = [0xab; 32];
        let memo = [0u8; 112];
        let plot_path = std::env::temp_dir().join("pos2_chia_test_k20.plot");

        if !plot_path.exists() {
            create_v2_plot(&plot_path, k, strength, &plot_id, index, meta_group, &memo)
                .expect("create_v2_plot");
        }

        let prover = Prover::new(&plot_path).expect("open prover");
        assert_eq!(prover.size(), k);
        assert_eq!(prover.get_strength(), strength);
        let plot_id = *prover.plot_id();

        let mut num_proofs = 0;
        let mut challenge = [0u8; 32];
        for challenge_idx in 0..300u32 {
            challenge[0..4].copy_from_slice(&challenge_idx.to_le_bytes());

            let qualities = prover
                .get_qualities_for_challenge(&challenge)
                .expect("get_qualities_for_challenge");

            for quality in qualities {
                let proof = solve_proof(&quality, &plot_id, k, strength);
                assert!(!proof.is_empty(), "failed to solve proof");
                num_proofs += 1;
                let validated = validate_proof_v2(&plot_id, k, &challenge, strength, &proof);
                assert!(
                    validated.is_some(),
                    "proof should validate for challenge {challenge_idx}",
                );
                let recovered = quality_string_from_proof(&plot_id, k, strength, &proof);
                let recovered = recovered.expect("quality_string_from_proof");
                assert_eq!(
                    quality.chain_links, recovered.chain_links,
                    "challenge {challenge_idx}: quality roundtrip must match",
                );
            }
        }
        assert_eq!(num_proofs, 539);
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

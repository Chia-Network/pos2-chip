// returns the compacted buffer as well as the number of tail bits still unused
pub(crate) fn compact_bits(x_values: &[u32], k: u8, tail: u8) -> Vec<u8> {
    // each u32 is only using k-bits. pack them to make the proof smaller

    // the tail is used to encode the strength, which is expected to only need 2 or 3 bits.
    let tail_bits = (8 - tail.leading_zeros()) as u8;
    let mut full_proof = Vec::<u8>::with_capacity(
        (x_values.len() * usize::from(k) + usize::from(tail_bits)).div_ceil(8),
    );

    let mut val = 0_u8;
    let mut bits_left = 8;
    for x in x_values {
        let mut mask = ((1_u64 << k) - 1) as u32;
        let mut x_bits = k;
        // we don't expect any other bits to be set
        assert!((x | mask) == mask);

        while x_bits > 0 {
            let bits_to_copy = std::cmp::min(bits_left, x_bits);

            if x_bits > bits_left {
                val |= ((x & mask) >> (x_bits - bits_left)) as u8;
            } else {
                val |= ((x & mask) << (bits_left - x_bits)) as u8;
            }

            mask >>= bits_to_copy;
            bits_left -= bits_to_copy;
            x_bits -= bits_to_copy;

            if bits_left == 0 {
                full_proof.push(val);
                val = 0;
                bits_left = 8;
            }
        }
    }

    // note that the tail value is not left-aligned, it's right-aligned since
    // we try to use the tail padding of zero-bits to store it
    if tail_bits > 0 {
        if tail_bits <= bits_left {
            val |= tail;
            full_proof.push(val);
        } else if bits_left < 8 {
            full_proof.push(val);
            full_proof.push(tail);
        } else {
            full_proof.push(tail);
        }
    } else if bits_left < 8 {
        full_proof.push(val);
    }

    full_proof
}

/// extracts all k-size values from the proof buffer and returns them as a
/// vector of u32 as well as the residual value in the tail, which has fewer
/// than k-bits
pub(crate) fn expand_bits(proof: &[u8], num_values: usize, k: u8) -> (Vec<u32>, u32) {
    let mut x_values = Vec::<u32>::with_capacity(proof.len() * 8 / usize::from(k));

    let mut val = 0_u32;
    let mut bits_left = k;
    let mut reading_tail = false;
    'outer: for byte in proof {
        let mut byte_bits = 8;
        let mut byte_mask = 0xff_u8;

        while byte_bits > 0 {
            if bits_left > byte_bits {
                val |= u32::from(byte & byte_mask) << (bits_left - byte_bits);
            } else {
                val |= u32::from(byte & byte_mask) >> (byte_bits - bits_left);
            }
            let bits_copied = std::cmp::min(byte_bits, bits_left);
            bits_left -= bits_copied;
            byte_bits -= bits_copied;
            if byte_bits > 0 {
                byte_mask >>= bits_copied;
            }
            if bits_left == 0 {
                if reading_tail {
                    break 'outer;
                }
                x_values.push(val);
                bits_left = k;
                val = 0;
                if x_values.len() == num_values {
                    bits_left = 32;
                    reading_tail = true;
                }
            }
        }
    }

    // we align the tail value to be a proper integer
    if bits_left < 32 {
        val >>= bits_left;
    }

    (x_values, val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn print_bits(input: &[u8]) -> String {
        let mut ret = String::new();
        for b in input {
            ret += format!("{b:08b}").as_str();
        }
        ret
    }

    #[rstest]
    fn compact_bits_fields(
        #[values(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 28, 29, 30, 31, 32
        )]
        num_bits: u8,
        #[values(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)] field: u32,
        #[values(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 23, 26, 28, 33, 63, 64, 100, 200, 240, 255
        )]
        tail: u8,
    ) {
        // make sure each field is confined to exactly "num_bits" bits
        let mask: u32 = 0xffffffff >> (32 - num_bits);
        let mut input = [0_u32; 11];
        input[field as usize] = mask;

        let zero = "0".repeat(num_bits.into());
        let one = "1".repeat(num_bits.into());

        let mut expect = String::new();
        for i in 0..11 {
            if i == field {
                expect += &one;
            } else {
                expect += &zero;
            }
        }
        let tail_string = if tail == 0 {
            String::default()
        } else {
            format!("{tail:b}")
        };
        let padding = (expect.len() + tail_string.len()) % 8;
        let mut padding = if padding == 0 { padding } else { 8 - padding };
        while padding > 0 {
            expect += "0";
            padding -= 1;
        }
        expect += &tail_string;

        let bits = compact_bits(&input, num_bits, tail);
        assert_eq!(print_bits(bits.as_slice()), expect);

        let (round_trip, round_trip_tail) = expand_bits(bits.as_slice(), 11, num_bits);
        assert_eq!(round_trip, input);
        assert_eq!(round_trip_tail, tail as u32);
    }

    #[rstest]
    fn compact_bits_values(
        #[values(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)] num_bits: u8,
        #[values(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 23, 26, 28, 33, 63, 64, 100, 200, 240, 255
        )]
        tail: u8,
    ) {
        // make sure the values are preserved
        let mask: u32 = 0xffffffff >> (32 - num_bits);
        let mut input = [0_u32; 11];

        let mut expect = String::new();
        for (idx, ref mut v) in &mut input.iter_mut().enumerate() {
            **v = idx as u32 & mask;
            let bits = format!("{:0width$b}", idx as u32 & mask, width = num_bits as usize);
            expect += bits.as_str();
        }

        let tail_string = if tail == 0 {
            String::default()
        } else {
            format!("{tail:b}")
        };
        let padding = (expect.len() + tail_string.len()) % 8;
        let mut padding = if padding == 0 { padding } else { 8 - padding };
        while padding > 0 {
            expect += "0";
            padding -= 1;
        }
        expect += &tail_string;

        let result = compact_bits(&input, num_bits, tail);
        assert_eq!(print_bits(result.as_slice()), expect);

        let (round_trip, round_trip_tail) = expand_bits(result.as_slice(), 11, num_bits);
        assert_eq!(round_trip, input);
        assert_eq!(round_trip_tail, tail as u32);
    }
}

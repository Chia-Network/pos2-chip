# Expected Number of Set Checks to Recover All 60 Valid Proof Fragments

We start with 60 valid proof fragments (each originally 56 bits). We apply a bit drop of N bits where N ∈ {1,…,16}.

## Candidates per proof
Dropping N bits produces M = 2^N candidate fragments per original proof. Exactly one of the M candidates is the true valid fragment; the other M−1 are invalid. There are 60 independent buckets (one per original proof), each with M candidates. We process each bucket independently and stop as soon as the valid candidate is known (if M−1 candidates have been rejected, the last is valid by elimination).

## Candidate checking procedure
Each candidate carries two internal filter sets: Set A and Set B.
- Check Set A.
- If Set A passes, check Set B.
- If both pass, a final full proof check is done (not counted here).

Assumptions:
- For an invalid candidate, each set (A or B) fails independently with probability 1/e.
- For a valid candidate, both sets always pass.
- We count only set checks (A and B), not the final full proof check.

## Expected cost per candidate
For an invalid candidate:
- With probability 1/e: Set A fails → 1 set checked.
- With probability 1−1/e: Set A passes, then Set B → 2 sets checked.

Let c be the expected sets for an invalid candidate:
c = 1·(1/e) + 2·(1 − 1/e) = 2 − 1/e ≈ 1.6321.

For a valid candidate, if tested it always costs 2 set checks; however, it may not be tested when it is the last remaining candidate.

## Number of candidates tested in a bucket
Let M = 2^N and the valid candidate’s random position K ∈ {1,…,M} be uniform. We test in order until the valid is found:
- If K < M: test K candidates (including the valid).
- If K = M: test M−1 candidates (last one deduced).

Expected tested candidates:
E[T] = (M + 1)/2 − 1/M.

Expected invalid candidates tested:
E[invalid tested] = (M − 1)/2.

## Expected set checks per bucket
Invalid tested candidates cost c sets on average; the valid candidate is tested with probability (M − 1)/M, costing 2 sets when tested. Therefore:
E[sets per bucket] = c·(M − 1)/2 + 2·(M − 1)/M.

Equivalently:
E[sets per bucket] = ((M − 1)·(c·M + 4)) / (2·M),
where M = 2^N and c = 2 − 1/e.

## Total expected set checks for 60 proofs
E[total sets for 60 proofs] = 60 · ((M − 1)·(c·M + 4)) / (2·M).

## Concrete values for N = 1…16

Below is a table of the expected total number of set checks needed to recover all 60 valid proof fragments, for different bit-drop amounts \(N\).

- \(N\): number of bits dropped
- \(2^N\): candidates per original proof
- “Sets per proof” = expected set checks per bucket
- “Total sets” = expected set checks across all 60 proofs

(All values rounded to the nearest integer.)

| N | Candidates per proof ( \(2^N\) ) | Expected sets per proof | Expected sets total (60 proofs) | Expected validations per proof | Expected validations total (60 proofs) |
|---|----------------------------------:|------------------------:|--------------------------------:|-------------------------------:|---------------------------------------:|
| 1  | 2        | 2     | 109      | 1    | 60       |
| 2  | 4        | 4     | 237      | 1    | 81       |
| 3  | 8        | 7     | 448      | 2    | 136      |
| 4  | 16       | 14    | 847      | 4    | 236      |
| 5  | 32       | 27    | 1,634    | 7    | 430      |
| 6  | 64       | 53    | 3,203    | 14   | 814      |
| 7  | 128      | 106   | 6,337    | 26   | 1,582    |
| 8  | 256      | 210   | 12,605   | 52   | 3,118    |
| 9  | 512      | 419   | 25,140   | 103  | 6,185    |
| 10 | 1,024    | 837   | 50,210   | 205  | 12,323   |
| 11 | 2,048    | 1,672 | 100,348  | 410  | 24,598   |
| 12 | 4,096    | 3,344 | 200,626  | 819  | 49,148   |
| 13 | 8,192    | 6,686 | 401,181  | 1,637| 98,248   |
| 14 | 16,384   | 13,372| 802,291  | 3,274| 196,447  |
| 15 | 32,768   | 26,742| 1,604,511| 6,547| 392,847  |
| 16 | 65,536   | 53,483| 3,208,951| 13,094| 785,646 |

## Expected validation checks (final proof checks)

We count how many times a candidate reaches the final validation check (after both sets pass).

Let:
- \(N\) = bit-drop amount, \(M = 2^N\) candidates per proof (bucket).
- There are 60 buckets.
- For invalid candidates, each set passes with probability \(1 - 1/e\), so both pass with probability:
  \[
  q = (1 - 1/e)^2 \approx 0.3995764.
  \]
- The valid candidate, if tested, always reaches validation.
- We stop as soon as the valid candidate is known; the last candidate is not tested.

Per bucket:
- Expected invalid candidates tested: \((M - 1)/2\).
- Expected validations from invalids: \((M - 1)/2 \cdot q\).
- Valid candidate is tested with probability \((M - 1)/M\), contributing \( (M - 1)/M \) validations.

Therefore:
\[
\mathbb{E}[\text{validations per proof}] = \frac{M - 1}{2}\,q + \frac{M - 1}{M}, \quad M = 2^N,\; q = (1 - 1/e)^2.
\]

For all 60 proofs:
\[
\mathbb{E}[\text{total validations}] = 60 \left( \frac{M - 1}{2}\,(1 - 1/e)^2 + \frac{M - 1}{M} \right), \quad M = 2^N.
\]

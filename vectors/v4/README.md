# vectors/v4/

The v4 vector directory for the S-01 suite. It is built first from the
N-09b incremental piece; when the full v4 set arrives, re-source this
directory from it and re-run the suite.

## Contents

* `n-09b.json` -- the N-09b contrast vector entry (base P-01, same message,
  only the verification moment varies: T0+300 ACCEPT, T0+301 REJECT 400
  with WINDOW / E_WINDOW_OUTSIDE). Identical to the N-09b entry in
  `tests/fixtures/vectors.json`; see `catalog.json` for its MD5.
* `catalog.json` -- the v4 catalog: source (N-09b incremental piece,
  MD5 13225715), counts (total 29, positive 6, negative 23 -- up from
  22 with N-09b -- probe 6, judged 23), and the vector id list.

## Use

Load a vector from this directory with
`agent_auth_verifier.load_contrast_vector` (or `run_contrast_from_file`);
the entry is registered in the vector set by id and its base vector
resolves from the set. The contrast runner
(`agent_auth_verifier.run_contrast`) runs each evaluation independently
through the full judgment chain and reports the section 2.2 stepwise
table and any CONTRAST_ANOMALY.

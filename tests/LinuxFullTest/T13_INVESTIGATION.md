# T13 resolver failure fixture

## Root cause

T13 previously sent a Trojan request with synthetic invalid authentication and
required an upstream DNS failure. Authentication failure selects the H3 fallback;
it does not make arbitrary stream bytes valid H3. `forward_to_h1_upstream` feeds
nghttp3 before starting the upstream TCP resolver. An H3 parser error resets the
request stream and posts handler destruction. That destruction can cancel the
resolver or suppress its callback. Missing DNS failure is therefore valid for
this malformed input, not evidence of a DNS or padding regression.

For the old public synthetic T13 input, the ASCII authentication prefix decodes
as an unknown H3 frame type 8806, length 48 (three-byte frame header). At offset
51 another unknown frame has type 49, length 50; its payload ends at offset 103.
A short legacy request ends before that offset. Extending the same request to
1109 bytes with zeroes makes offset 103 a DATA frame (`00 00`) before HEADERS,
causing `ERR_H3_FRAME_UNEXPECTED`. This discriminates length/content without
changing authentication, transport timing, or segmentation. Random padding can
supply more bytes, but does not change fallback semantics. No claim that these
controlled zero bytes equal the original randomized padding is needed.

## Comparison and regression

Compared origin/master `90028d5` and branch `565c18f` using identical current
fixtures, local oversized resolver-failure hostname, and controlled aioquic
streams. Each binary: three short legacy inputs reached DNS failure; three
1109-byte zero-extended legacy inputs and three equally long command-5 inputs
hit H3 parser errors without DNS failure. Three truncated inputs on each binary
remained pending. Baseline does not implement client padding; enabling that
config key there is only a compatibility control, not actual padded traffic.

Old end-to-end fixture, three runs per binary/config: baseline padding off/on
6/6 passed; current padding off 3/3 passed, on 2/3 passed in first matrix.
After isolated baseline rebuild, all 12 matrix cases passed. These small counts
are reproduction evidence, not a probability estimate. Controlled long input
failed original T13's unchanged DNS assertion deterministically (RED).

Fixed T13 sends T4's valid H3 GET, requires client-visible 502 plus original DNS
failure log and server survival, and rejects H3 parser errors. Shared T4 helper
now prints response status. No production code changes; T15 retains malformed
H3 rejection coverage. Current T13 passed 10/10 normally and 10/10 on one CPU;
baseline passed 10/10 initially and one isolated rebuilt run. Two sequential
QUIC suites passed 29/29 each, including T4/T12/T13/T15. All 13 root Python
unit/regression scripts passed, with chrome transport rerun after cleanup.

Commands, full outputs, probe scripts, RED failure and intermediate failures:
`/home/hermes/work/logs/t13/` (`compare-isolated.log`,
`original-matrix-isolated.log`, `red-controlled.log`, `green-*.log`,
`suite-1.log`, `suite-2.log`, `units.log`, `chrome-unit-clean.log`).

## Validation incident and scope

Initial baseline source used a symlink for ngtcp2. CMake copied that symlink
into its patched build tree and unintentionally patched the shared submodule.
Diff was preserved as `unexpected-submodule.diff`, reversed exactly, and clean
submodule state verified. Baseline was rebuilt using a real isolated ngtcp2 copy;
controlled comparison and old-fixture matrix were rerun. Chrome unit initially
failed against contaminated source, then passed against restored source. No
submodule changes are included. First baseline build timed out; terminated
processes were checked and incremental build completed with a longer deadline.

Scope: resolver failure, not authentication rejection or exact original packet
segmentation. No production parser, fallback ordering, or padding changes justified.

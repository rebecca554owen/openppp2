# The VMUX fuzz targets

Coverage-guided fuzz targets for the vmux protocol input path. This is the
audit report's follow-up task **VMUX-FUZZ-001**: the report lists a coverage-
guided harness among the non-blocking work, and the two targets here cover the
two highest-risk surfaces it names.

## The targets

| Target | What it drives | What it asserts |
|---|---|---|
| `fuzz_vmux_ack` | the ACK frame decoder and the retransmit buffer's acknowledgement path | a decoded frame never grows the retained set, never breaks the byte cap, and never leaves the per-space byte total disagreeing with the entries that are actually still retained |
| `fuzz_vmux_frame` | one whole vmux frame through the session's command dispatcher | the dispatcher survives every byte: no crash, no hang, no session teardown |

The frame target is the other side of P2-8. That change made an unknown
command skip instead of taking the carrier down, and "skip" only means
something if the input path survives every byte it can be given.

The acknowledgement target is the scenario the report calls out by name: a
malicious ACK range going through the full session input path. The
hand-written cases in `vmux_qa001_ack_malicious_test` cover the shapes that
were thought of; the fuzzer covers the ones that were not.

## Building

The targets need the libFuzzer runtime, so they only build with a clang that
ships it:

- **Linux CI**: the `clang` from the distribution does. The workflow
  `.github/workflows/fuzz.yml` builds them.
- **macOS**: Apple's own clang does **not** ship the runtime. Use the
  Homebrew LLVM:
  ```bash
  cmake -S . -B build/vmux-fuzz -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
    -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
    -DENABLE_ASAN=ON \
    -DENABLE_VMUX_FUZZ_TEST=ON
  cmake --build build/vmux-fuzz --target fuzz_vmux_ack fuzz_vmux_frame
  ```
- **`-DENABLE_ASAN=ON`** is worth adding: it instruments the library itself,
  so a memory error inside the session is caught rather than merely a crash.
  It also disables jemalloc, which would otherwise fight the sanitizer.

## Running

```bash
bash scripts/run-vmux-fuzz.sh build/fuzz
```

The script runs each target for a bounded time against the checked-in corpus
and fails if either one finds something. The reproducer is left in the
crash directory (`build/fuzz/crash` by default). `FUZZ_TIME` changes the
budget in seconds.

To drive one target by hand:

```bash
./bin/fuzz_vmux_ack \
  -dict=tests/fuzz/dictionary/vmux.dict \
  -artifact_prefix=/tmp/crash/ \
  -max_total_time=300 \
  tests/fuzz/corpus/fuzz_vmux_ack
```

## The corpus and the dictionary

- `corpus/fuzz_vmux_ack/` -- ACK frames: a single block, two blocks, a frame
  with a hole in it, one at the range cap, a truncated one, one with a zero
  block count, one with trailing garbage.
- `corpus/fuzz_vmux_frame/` -- vmux frames: SYN, PUSH, ACK, FEC, an unknown
  command byte, and an empty payload.
- `dictionary/vmux.dict` -- the wire vocabulary, so the fuzzer spends its
  time on frames that look like frames instead of on random bytes.

The corpus in the tree is **curated**: the seeds that were written by hand.
The fuzzer works on a copy of it under the build directory, so a run does not
leave its own discoveries in the source tree -- it leaves them in the build
directory, where the workflow uploads them as an artifact. A finding that is
worth keeping becomes a seed in the tree, on purpose, in its own commit: that
is what makes a finding a regression rather than a story.

## Naming convention for what comes next

The audit report names seven targets: `fuzz_vmux_header`, `fuzz_syn`,
`fuzz_push`, `fuzz_ack`, `fuzz_fec`, `fuzz_mode_set`,
`fuzz_session_parser`. The two here cover the same ground at the level of the
whole path rather than per command; the per-command names stay available for
when one of them earns its own target.

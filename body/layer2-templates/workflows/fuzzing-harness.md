# AFL++ Fuzzing Harness Workflow

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** AFL++ fuzzing and protocol harness development

Use this workflow to build an AFL++ fuzzing harness. Prepare inputs, measure coverage, and connect each reproducible crash to evidence.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Setup     │ → │   Corpus    │ → │   Harness   │ → │   Execute   │ → │   Triage    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │                  │
 Build AFL++        Seed corpus      Write harness         Fuzz           Analyze crashes
```

---

## Stage 1: Environment Setup

### AFL++ Installation
```bash
# Clone and build AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install

# Verify installation
afl-fuzz --help
afl-clang-fast --version
```

### System Configuration
```bash
# Disable core pattern (for crash tracking)
echo core | sudo tee /proc/sys/kernel/core_pattern

# Disable CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Increase open file limit
ulimit -n 65535
```

### Docker Alternative
```dockerfile
FROM aflplusplus/aflplusplus:latest

WORKDIR /fuzzing
COPY . .

# Build target with instrumentation
RUN afl-clang-fast -o target target.c
```

### Deliverable
- [ ] AFL++ installed and configured
- [ ] System optimized for fuzzing

---

## Stage 2: Target Analysis

### Identify Entry Points
```bash
# Find parsing functions
grep -rn "parse\|read\|decode\|deserialize" src/

# Find input handlers
grep -rn "recv\|read\|fread\|accept" src/

# Find format-specific handlers
grep -rn "json\|xml\|tlv\|protobuf" src/
```

### Determine Input Format
````markdown
## Target Input Analysis

**Format:** [Binary/Text/Protocol]
**Structure:**
- [Header fields]
- [Variable-length sections]
- [Checksums/validation]

**Parsing Flow:**
1. [First function called]
2. [Validation steps]
3. [Data extraction]
```

### Identify Interesting Code Paths
```c
// Look for:
// - Memory allocations based on input
malloc(input_size);

// - Buffer operations
memcpy(dst, src, len);

// - Arithmetic on user data
index = user_input * multiplier;

// - Format strings
printf(user_string);

// - State transitions
state = parse_state(input);
````

### Deliverable
- [ ] `target-analysis.md` - Entry points and input format
- [ ] List of interesting functions to cover

---

## Stage 3: Seed Corpus Creation

### Capture Valid Samples
```bash
# Network protocol capture
tcpdump -i eth0 -w capture.pcap port 12345
# Extract payloads
tshark -r capture.pcap -T fields -e data > payloads.hex

# File format samples
find /samples -name "*.target" -exec cp {} corpus/ \;

# Generate from spec
python3 generate_valid_samples.py > corpus/seed001
```

### Corpus Structure
```
corpus/
├── valid/           # Known-good inputs
│   ├── minimal.bin  # Smallest valid input
│   ├── typical.bin  # Normal use case
│   └── complex.bin  # Full-featured input
├── edge_cases/      # Boundary conditions
│   ├── empty.bin
│   ├── max_size.bin
│   └── special_chars.bin
└── coverage/        # Inputs that hit specific paths
    ├── path_a.bin
    └── path_b.bin
```

### Corpus Minimization
```bash
# Minimize with AFL++
afl-cmin -i corpus/ -o corpus_min/ -- ./target @@

# Further minimize individual files
afl-tmin -i corpus_min/seed001 -o corpus_min/seed001_min -- ./target @@
```

### Protocol-Specific Seeds
```python
# Example: TLV8 seed generation for HomeKit
def generate_tlv_seed():
    tlv = b""
    tlv += b"\x00\x01\x01"      # State = 1
    tlv += b"\x06\x10" + os.urandom(16)  # PublicKey
    return tlv

with open("corpus/valid_tlv.bin", "wb") as f:
    f.write(generate_tlv_seed())
```

### Deliverable
- [ ] `corpus/` - Minimized seed corpus
- [ ] `corpus.md` - Description of each seed

---

## Stage 4: Harness Development

### Basic File Harness
```c
// harness.c - Basic file input harness
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include target headers
#include "target.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }

    // Read input file
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    // Call target function
    target_parse(buf, len);

    free(buf);
    return 0;
}
```

### Persistent Mode Harness (10x faster)
```c
// harness_persistent.c - AFL++ persistent mode
#include <stdio.h>
#include <unistd.h>
#include "target.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // Reset state between iterations
        target_reset();

        // Call target
        target_parse(buf, len);
    }

    return 0;
}
```

### Network Protocol Harness
```c
// harness_network.c - Network protocol harness
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "target.h"

int main(int argc, char **argv) {
    // Simulate network input via file
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    char buf[65536];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    // Create mock socket context
    struct connection *conn = create_mock_connection();

    // Process as network message
    target_process_message(conn, buf, len);

    destroy_mock_connection(conn);
    return 0;
}
```

### Compile with Instrumentation
```bash
# Standard instrumentation
afl-clang-fast -o harness harness.c target.c -I./include

# With sanitizers (slower but catches more)
afl-clang-fast -fsanitize=address,undefined -o harness_asan harness.c target.c

# With coverage tracking
afl-clang-fast -fprofile-instr-generate -fcoverage-mapping -o harness_cov harness.c target.c
```

### Deliverable
- [ ] `harness.c` - Compiled harness
- [ ] `harness_asan` - ASAN-instrumented build
- [ ] `Makefile` - Build automation

---

## Stage 5: Fuzzing Execution

### Single-Core Fuzzing
```bash
# Basic run
afl-fuzz -i corpus/ -o findings/ -- ./harness @@

# With dictionary
afl-fuzz -i corpus/ -o findings/ -x dict.txt -- ./harness @@

# With timeout
afl-fuzz -i corpus/ -o findings/ -t 1000 -- ./harness @@
```

### Multi-Core Fuzzing
```bash
# Master instance
afl-fuzz -i corpus/ -o findings/ -M main -- ./harness @@

# Secondary instances (one per core)
afl-fuzz -i corpus/ -o findings/ -S fuzzer01 -- ./harness @@
afl-fuzz -i corpus/ -o findings/ -S fuzzer02 -- ./harness @@
afl-fuzz -i corpus/ -o findings/ -S fuzzer03 -- ./harness @@

# Check status
afl-whatsup findings/
```

### Power Schedule Selection
```bash
# Explore scheduler (default, good for new targets)
afl-fuzz -p explore -i corpus/ -o findings/ -- ./harness @@

# Exploit scheduler (good when corpus is mature)
afl-fuzz -p exploit -i corpus/ -o findings/ -- ./harness @@

# Rare branch focus
afl-fuzz -Z -i corpus/ -o findings/ -- ./harness @@
```

### Custom Mutators
```c
// custom_mutator.c - AFL++ custom mutator
#include "afl-fuzz.h"

size_t afl_custom_mutator(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf,
    size_t add_buf_size,
    size_t max_size
) {
    // Protocol-aware mutations
    *out_buf = buf;

    // Example: TLV type/length mutations
    if (buf_size >= 2) {
        buf[0] ^= 0xff;  // Flip type byte
        buf[1] = rand() % 256;  // Random length
    }

    return buf_size;
}
```

```bash
# Run with custom mutator
AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutator.so afl-fuzz -i corpus/ -o findings/ -- ./harness @@
```

### Deliverable
- [ ] Fuzzing campaign running
- [ ] `findings/` directory with outputs

---

## Stage 6: Monitoring & Metrics

### Real-Time Monitoring
```bash
# Watch AFL++ status
watch -n 1 afl-whatsup findings/

# Monitor crash directory
watch -n 5 'ls -la findings/*/crashes/'

# Coverage over time
afl-plot findings/ plot_output/
```

### Key Metrics to Track
```
┌────────────────────────────────────────────────────┐
│ Metric              │ Good       │ Warning         │
├─────────────────────┼────────────┼─────────────────┤
│ exec/sec            │ > 100      │ < 10            │
│ stability           │ > 90%      │ < 80%           │
│ new paths           │ Growing    │ Stalled > 1hr   │
│ crashes             │ 0 or few   │ Many unique     │
│ hangs               │ 0          │ Growing         │
└────────────────────────────────────────────────────┘
```

### Troubleshooting Low Performance
| Issue | Cause | Fix |
|-------|-------|-----|
| Low exec/sec | Slow target | Use persistent mode |
| Low stability | Non-determinism | Fix random, time deps |
| No new paths | Poor corpus | Add more seeds |
| Many timeouts | Slow paths | Increase timeout |

### Deliverable
- [ ] `metrics.md` - Periodic metrics snapshots
- [ ] `afl-plot` output graphs

---

## Stage 7: Crash Triage

### Initial Classification
```bash
# List crashes
ls findings/*/crashes/

# Quick dedupe by stack
for crash in findings/*/crashes/*; do
    echo "=== $crash ==="
    ./harness_asan "$crash" 2>&1 | head -20
done | tee crash_stacks.txt

# Unique stack signatures
grep -A5 "SUMMARY:" crash_stacks.txt | sort -u
```

### ASAN Analysis
```bash
# Run crash with ASAN
./harness_asan findings/main/crashes/id:000000,* 2>&1 | tee crash_000000.txt

# Parse ASAN output
grep -E "(ERROR|SUMMARY|READ|WRITE)" crash_000000.txt
```

### Crash Minimization
```bash
# Minimize crash input
afl-tmin -i findings/main/crashes/id:000000 -o crash_min.bin -- ./harness @@

# Verify minimized crash reproduces
./harness_asan crash_min.bin
```

### Root Cause Analysis
````markdown
## Crash Analysis: [ID]

**Crash Type:** [heap-buffer-overflow / stack-buffer-overflow / use-after-free / null-deref]
**ASAN Error:**
```
[ASAN output snippet]
```

**Input:** [Hex dump or description]
**Minimal Repro:** crash_min.bin

**Vulnerable Code:**
```c
// File: src/parser.c:123
memcpy(dst, src, user_len);  // user_len not validated
```

**Root Cause:**
[Explanation]

**Severity:** [Critical/High/Medium/Low]
**Exploitability:** [Yes/Unlikely/No]
````

### Deliverable
- [ ] `crashes/` - Minimized crash inputs
- [ ] `triage.md` - Crash analysis report

---

## Stage 8: Coverage Analysis

### Generate Coverage Report
```bash
# Run corpus through instrumented binary
LLVM_PROFILE_FILE=coverage.profraw ./harness_cov corpus/*

# Merge profiles
llvm-profdata merge -sparse coverage.profraw -o coverage.profdata

# Generate HTML report
llvm-cov show ./harness_cov -instr-profile=coverage.profdata \
    --format=html -output-dir=coverage_html/
```

### Identify Uncovered Code
```bash
# Text report of uncovered lines
llvm-cov report ./harness_cov -instr-profile=coverage.profdata

# Export to lcov format
llvm-cov export ./harness_cov -instr-profile=coverage.profdata \
    -format=lcov > coverage.lcov
```

### Deliverable
- [ ] `coverage_html/` - Coverage report
- [ ] List of uncovered critical functions

---

## Quick Reference

### AFL++ Command Cheatsheet
```bash
# Basic fuzz
afl-fuzz -i in/ -o out/ -- ./target @@

# With dictionary
afl-fuzz -i in/ -o out/ -x dict.txt -- ./target @@

# ASAN build
afl-clang-fast -fsanitize=address -o target_asan target.c

# Minimize corpus
afl-cmin -i in/ -o in_min/ -- ./target @@

# Minimize crash
afl-tmin -i crash.bin -o crash_min.bin -- ./target @@

# Status check
afl-whatsup out/
```

### File Layout
```
fuzzing/
├── corpus/              # Seed inputs
├── findings/            # AFL++ output
│   ├── main/
│   │   ├── queue/       # Interesting inputs
│   │   ├── crashes/     # Crash inputs
│   │   └── hangs/       # Timeout inputs
│   └── fuzzer0N/        # Secondary fuzzer outputs
├── harness.c            # Fuzz harness source
├── harness              # Compiled harness
├── harness_asan         # ASAN-instrumented
├── dict.txt             # Fuzzing dictionary
└── triage/              # Crash analysis
```

### Common CWEs from Fuzzing
| CWE | Description | ASAN Error |
|-----|-------------|------------|
| CWE-122 | Heap overflow | heap-buffer-overflow |
| CWE-121 | Stack overflow | stack-buffer-overflow |
| CWE-416 | Use after free | heap-use-after-free |
| CWE-476 | NULL dereference | SEGV on null |
| CWE-190 | Integer overflow | Varies |

---

## Checklist

- [ ] AFL++ installed and system configured
- [ ] Target analyzed and entry points identified
- [ ] Seed corpus created and minimized
- [ ] Harness developed and tested
- [ ] Instrumented builds created (standard + ASAN)
- [ ] Fuzzing campaign running
- [ ] Metrics being monitored
- [ ] Crashes triaged
- [ ] Coverage analyzed
- [ ] Report generated

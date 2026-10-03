# E2E Attack Chain Testing Plan — `android-gif-drawable` GifTexImage2D Heap Overflow

## Objective

Turn the confirmed integer-overflow → heap-buffer-overflow primitive in
`GifTexImage2D` (v1.2.32) into a fully characterised end-to-end attack chain
tested exclusively on owned Android emulator instances. The output is
reproducible evidence and an instrumented Android app that demonstrates each
stage of the chain, suitable for inclusion in the coordinated disclosure report.

All testing MUST run inside emulator instances you own (emulator-5560 or fresh
AVDs). No real devices, no third-party infrastructure.

---

## Phase 0 — Environment & Safety Constraints

### Emulator matrix

| Config ID | Arch | API | Image | Purpose |
|-----------|------|-----|-------|---------|
| `emu-arm32` | armeabi-v7a | 28–30 | Google APIs (no Play) | Primary 32-bit corruption chain |
| `emu-x86` | x86 | 28–30 | Google APIs (no Play) | Cross-arch confirmation |
| `emu-arm64` | arm64-v8a | 34 | Google APIs | 64-bit DoS / OOM path |

### Build variants

For each arch, build the harness app in **three** configurations:

1. **ASan-instrumented** (`-fsanitize=address`): precise fault attribution.
2. **Debug-symbols, no sanitiser**: realistic heap behaviour, allows GDB/LLDB
   attach via `adb forward` + `gdbserver`.
3. **Release (stripped)**: matches what real consumers ship; validates that the
   chain works without debug affordances.

### Safety rules

- The crafted GIF and test APKs never leave the local machine / emulator.
- The HTTP server serving the GIF listens on `10.0.2.2` (host loopback from
  emulator's perspective) only.
- No payloads that touch the network, contacts, SMS, or any real user data.
- Every payload's "proof of exploitation" action is writing a unique marker
  string to logcat (`I/PONEGLYPH_E2E: STAGE_N_REACHED`), nothing destructive.

---

## Phase 1 — Heap Corruption Characterisation

**Goal:** Map the exact corruption primitive — what you write, where, and how
much control the GIF format gives you.

### 1.1 Baseline allocation anatomy

```
Tasks:
1. Under ASan, log the returned pointer and requested size for
   `malloc(width * height * sizeof(argb))` at opengl.c:105.
   - Confirm: for 32768×32768 on 32-bit, requested size = 0 → allocator
     returns a minimum-region (1 or 16 bytes depending on allocator).
2. Log the actual usable size (`malloc_usable_size(ptr)`) to know the real
   allocation footprint.
3. Record the heap page/arena the allocation lands in.
```

### 1.2 Write-primitive geometry

```
Tasks:
1. Instrument `blitNormal()` (drawing.c:28) to log:
   - destination offset from frameBuffer base on each pixel write
   - value written (RGB triple)
   - total bytes written past allocation end
2. Vary the contained-image dimensions in the GIF and record how the
   overflow extent and write pattern change:
   - 1×1 contained image → minimal overflow
   - 100×100 → moderate
   - 200×1 → linear stride pattern
   - 1×200 → column pattern
3. Map the relationship:
   overflow_bytes = f(contained_width, contained_height, logical_width)
   Confirm the stride is `logical_width * 4`.
4. Vary pixel colours in the contained image. Confirm the written bytes
   are fully attacker-controlled RGB triples (from the GIF colour table
   and LZW stream).
```

### 1.3 Heap-neighbourhood survey

```
Tasks:
1. Under the non-ASan debug build, use GDB to inspect the 4 KiB region
   after the returned frameBuffer pointer before and after decoding.
   Record what heap metadata and adjacent allocations are present.
2. Identify what objects the library itself allocates near the frameBuffer:
   - GifInfo struct
   - colour table copies
   - LZW decode buffers
   - TexImageDescriptor
   Instrument each allocation site with address + size logging.
3. Repeat 20 times and note allocation-order stability (ASLR affects base
   but relative layout within an arena tends to be stable for same-thread
   sequential mallocs).
```

**Deliverable:** A table mapping (contained-image-W, contained-image-H) →
(overflow-bytes, byte-values, heap-objects-overwritten).

---

## Phase 2 — Adjacent-Object Corruption Analysis

**Goal:** Determine which library-internal objects can be reliably corrupted
and what that corruption enables.

### 2.1 Corruption target identification

```
Tasks:
1. From Phase 1.3, rank adjacent objects by:
   a. Reliability of adjacency (how often they land right after frameBuffer)
   b. Exploitability: does the object contain
      - function pointers or vtable pointers?
      - buffer pointers + length fields?
      - file descriptors or JNI references?
   c. Time-of-use: is the corrupted field read after the overflow write
      completes, during the same decode cycle?
2. Trace the code path from blitNormal() return through drawFrame() and
   back to Java. List every field read from each adjacent object along
   that path.
3. For the most promising target object, craft a GIF whose pixel RGB
   bytes overwrite that object's critical field with a controlled value.
   Verify the controlled value appears in the register / memory location
   at point-of-use via GDB breakpoint.
```

### 2.2 Control-flow influence test

```
Tasks:
1. If a function pointer or indirect-call target is reachable:
   - Overwrite it with 0x41414141 and confirm the crash PC shows the
     controlled value (SIGILL / SIGSEGV at 0x41414141).
   - Log: "I/PONEGLYPH_E2E: CONTROLLED_PC=0x41414141"
2. If a data pointer is reachable:
   - Overwrite it to point to a known string constant in .rodata.
   - Confirm the code dereferences the new pointer and reads the
     string (log the first 8 bytes).
   - Log: "I/PONEGLYPH_E2E: DATA_REDIRECT_OK"
3. If neither direct control-flow nor data-pointer corruption is
   immediate, document the gap and assess whether a multi-step
   strategy (e.g., corrupting a length field to enable a secondary
   overread/overwrite) is feasible.
```

**Deliverable:** Proof-of-concept GIF that achieves either controlled PC
or controlled data-pointer dereference, with logcat + GDB evidence.

---

## Phase 3 — Heap-Layout Manipulation ("Heap Shaping")

**Goal:** Determine whether the attacker can influence which objects are
adjacent to the frameBuffer allocation by controlling app-level behaviour
before the GIF is loaded.

### 3.1 Allocation-order influence

```
Tasks:
1. In the test app, vary the sequence of operations before loading the
   GIF:
   a. Load and discard N small GIFs first (primes the allocator).
   b. Allocate and free Java-side byte arrays of specific sizes.
   c. Trigger garbage collection between steps.
   Record how each sequence changes the heap neighbourhood of
   frameBuffer.
2. Identify a reproducible "spray" pattern that places a target object
   (from Phase 2.1) immediately after the frameBuffer allocation at
   least 8/10 times.
3. Document the spray as a deterministic setup sequence in the test app.
```

### 3.2 Multi-GIF interaction

```
Tasks:
1. Test whether loading multiple GifTexImage2D instances interleaves
   their allocations in a useful way. For example:
   - GIF-A: normal 100×100 → allocates a legitimate frameBuffer
   - GIF-B: overflow GIF → tiny allocation, overflows into GIF-A's
     structures
2. If interleaving works, this is a stronger primitive because the
   target objects are well-defined library structures with known layout.
```

**Deliverable:** Reproducible heap-layout setup code in the test app,
with statistical reliability measurements (N runs, success rate).

---

## Phase 4 — End-to-End Chain Assembly

**Goal:** Wire phases 1–3 into a single deterministic sequence from remote
GIF fetch to proof-of-impact.

### 4.1 Chain stages

```
Stage 0: TRIGGER
  - Emulator app fetches crafted GIF from host HTTP server.
  - Log: "I/PONEGLYPH_E2E: STAGE_0_TRIGGER fetched=156 bytes"

Stage 1: ALLOCATOR CONFUSION
  - GifTexImage2D allocates 0-byte (or minimum) frameBuffer.
  - Log: "I/PONEGLYPH_E2E: STAGE_1_ALLOC ptr=0x... usable=N"

Stage 2: HEAP OVERFLOW
  - blitNormal() writes attacker-controlled bytes past allocation.
  - Log: "I/PONEGLYPH_E2E: STAGE_2_OVERFLOW bytes_past=N"

Stage 3: CORRUPTION
  - Adjacent object's critical field now holds attacker-controlled value.
  - Log: "I/PONEGLYPH_E2E: STAGE_3_CORRUPT target_field=0x..."

Stage 4: IMPACT
  - Corrupted field is consumed: controlled PC, data redirect, or
    secondary primitive triggered.
  - Log: "I/PONEGLYPH_E2E: STAGE_4_IMPACT type=CONTROLLED_PC/DATA_REDIRECT"

Stage 5: PROOF
  - If PC control is achieved: redirect to a "proof gadget" — a small
    function in the test app that writes a unique marker:
    void proof() { __android_log_print(ANDROID_LOG_INFO,
        "PONEGLYPH_E2E", "STAGE_5_CODE_EXEC_PROOF uid=%d pid=%d",
        getuid(), getpid()); }
  - If data-redirect only: demonstrate read of otherwise-inaccessible
    memory region and log its content hash.
  - Log: "I/PONEGLYPH_E2E: STAGE_5_PROOF ..."
```

### 4.2 Single-script orchestration

```
Tasks:
1. Write a shell script (e2e_chain.sh) that:
   a. Boots the target emulator (or connects to running instance).
   b. Installs the instrumented test APK.
   c. Starts the local HTTP server with the crafted GIF.
   d. Triggers the app via adb shell am start / deep link.
   e. Collects logcat with grep for PONEGLYPH_E2E lines.
   f. Asserts all STAGE_0 through STAGE_5 markers appear in order.
   g. Saves full logcat, tombstone (if any), and GDB session log to
      findings/e2e_run_<timestamp>/.
   h. Repeats for each emulator config in the matrix.
2. The script should have a --dry-run mode that validates the setup
   without deploying the overflow GIF (uses the benign control instead)
   to confirm the pipeline works.
3. Exit codes: 0 = all stages reached; 1 = partial chain; 2 = env error.
```

**Deliverable:** `e2e_chain.sh`, updated test APK, and a passing run log
for at least one 32-bit emulator configuration.

---

## Phase 5 — Impact Boundary Testing

**Goal:** Establish the realistic attack surface — which real-world app
integration patterns are exploitable.

### 5.1 Integration-pattern matrix

```
Test each loading pattern with the overflow GIF:

| Pattern | API | Expectation |
|---------|-----|-------------|
| GifTexImage2D (OpenGL) | Direct | Primary chain (Phase 4) |
| GifDrawable (Canvas) | Direct | Separate alloc in drawing.c — test if same overflow applies |
| GifTextureView | View-based | Wraps GifTexImage2D — should inherit vulnerability |
| GifImageView | View-based | Wraps GifDrawable — test independently |
| Movie-based fallback | android.graphics.Movie | Different parser — likely not affected, confirm |

For each: log whether overflow occurs, which allocation site is hit,
and whether the Phase 4 chain transfers.
```

### 5.2 Input-source matrix

```
Test the chain with each InputSource variant:

| Source | How | Remote? |
|--------|-----|---------|
| ByteArraySource | byte[] from HTTP response | Yes |
| FileSource | File written from HTTP, then loaded | Yes |
| AssetSource | Bundled in APK | No (local) |
| ContentResolverSource | content:// URI from another app | Yes |
| InputStreamSource | InputStream from socket | Yes |
| UriSource | file:// or content:// | Depends |

For each remote-capable source: confirm the overflow GIF reaches
GifTexImage2D without any dimension validation by the InputSource layer.
```

### 5.3 Mitigation interaction

```
Test on emulator images with:
1. SELinux enforcing (default) — does it prevent/detect the corruption?
2. seccomp filters — does bionic's seccomp block any syscall the chain
   needs?
3. MTE (ARMv8.5 Memory Tagging, if available in emulator) — does it
   catch the out-of-bounds write?
4. scudo allocator (default on recent Android) vs jemalloc (older) —
   how does allocator choice affect heap layout reliability?

For each: binary pass/fail, and if the mitigation catches it, at which
stage.
```

**Deliverable:** Completed matrices with per-cell pass/fail and notes.

---

## Phase 6 — Documentation & Evidence Package

### 6.1 Artefact checklist

```
findings/e2e/
├── e2e_chain.sh                    # Orchestration script
├── trigger_gifs/
│   ├── overflow_32768x32768.gif    # Primary trigger (156 bytes)
│   ├── benign_100x100.gif          # Control
│   ├── overflow_varied/            # Phase 1.2 dimension variants
│   └── heap_shaping_set/           # Phase 3 multi-GIF set (if used)
├── app/
│   ├── build.gradle
│   └── src/                        # Instrumented test app
├── native_harness/
│   ├── arm32_gif_opengl_repro.c    # Existing ASan harness
│   └── e2e_harness.c              # Extended with Phase 2–4 instrumentation
├── logs/
│   ├── emu-arm32_run_<ts>.log
│   ├── emu-x86_run_<ts>.log
│   └── emu-arm64_run_<ts>.log
├── heap_maps/
│   ├── allocation_table.csv        # Phase 1 data
│   ├── adjacency_stats.csv         # Phase 1.3 data
│   └── spray_reliability.csv       # Phase 3 data
├── screenshots/
│   ├── gdb_controlled_pc.png
│   └── logcat_all_stages.png
├── impact_matrices/
│   ├── integration_patterns.md
│   ├── input_sources.md
│   └── mitigations.md
└── REPORT_ADDENDUM.md              # Narrative tying it all together
```

### 6.2 Report addendum structure

```
1. Executive summary: "The heap-buffer-overflow primitive in GifTexImage2D
   is exploitable on 32-bit Android to achieve [controlled PC / data
   redirect / secondary primitive] via a 156-byte remotely-served GIF."
2. Chain walkthrough with stage-by-stage evidence.
3. Reliability: success rate across N runs, allocator sensitivity.
4. Attack-surface analysis: which integration patterns and input sources
   are exploitable.
5. Mitigation analysis: what catches it, what doesn't.
6. Revised severity assessment based on demonstrated impact.
```

---

## Execution Order & Dependencies

```
Phase 0 (env setup)
  └─► Phase 1 (characterisation) — no dependencies
       ├─► Phase 2 (corruption targets) — needs Phase 1 data
       │    └─► Phase 3 (heap shaping) — needs Phase 2 target
       │         └─► Phase 4 (E2E assembly) — needs Phases 1–3
       └─► Phase 5.1, 5.2 (surface matrices) — can run in parallel with 2–3
Phase 4 + Phase 5
  └─► Phase 6 (documentation)
```

Estimated effort: 2–3 focused sessions for Phases 1–4 on a single arch,
plus one session for Phase 5 matrices and documentation.

---

## Stop / Reassess Criteria

- If Phase 1.3 shows no stable adjacency: pivot to documenting the
  corruption primitive without a full chain; the heap-overflow + ASan
  evidence is already sufficient for Critical severity.
- If Phase 2 yields no reachable function/data pointer: document as
  "heap metadata corruption" and assess whether allocator-specific
  exploitation (unlink-style) is worth pursuing or whether the existing
  evidence is sufficient.
- If Phase 3 spray reliability stays below 50%: document the statistical
  difficulty and note it as a partial mitigation; the primitive is still
  real and the severity still holds.

At any stop point, the existing ASan reproduction, disassembly evidence,
and remote-trigger proof from the current report already support the
CVSS 8.8 / 9.8 rating. The E2E chain upgrades the evidence but is not
required for a valid disclosure.

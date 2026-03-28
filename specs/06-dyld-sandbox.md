# Spec 06: DYLD_INSERT_LIBRARIES Filesystem Sandbox

**Status:** Proposed
**Author:** bashguard
**Date:** 2026-03-27

---

## Problem

bashguard's current architecture is **cooperative**: it intercepts Claude's `Bash` PreToolUse hook and emits `deny` or `confirm` verdicts. Claude must obey those verdicts. If Claude ignores the hook (bug, jailbreak, misconfiguration), the dangerous command executes unimpeded.

Furthermore, bashguard only covers the `Bash` tool. Claude can also cause filesystem damage via:
- `Write` tool writing to destructive paths
- MCP tool calls that exec subprocesses
- Scripts it writes and then executes

**Goal:** Add a non-cooperative containment layer that catches what bashguard's hooks miss, without requiring kernel extensions, root, or OS-specific configuration.

---

## Background: Dynamic Linker Interposition

On macOS (and Linux), the dynamic linker resolves shared library symbols at load time. `DYLD_INSERT_LIBRARIES` (macOS) and `LD_PRELOAD` (Linux) instruct the linker to load a specified dylib/so *before* all others. When a symbol appears in both the injected library and libc, the injected version wins — this is **symbol interposition**.

This mechanism is used legitimately by:
- Memory allocator replacements (jemalloc, tcmalloc)
- Test frameworks (address sanitizer, valgrind)
- Security tools (runtime syscall monitoring)
- Development tools (leak detectors, call tracers)

### The relevant symbols

All filesystem-destructive operations in user space ultimately call through these libc symbols:

| Operation | libc symbol | Syscall |
|---|---|---|
| Delete file | `unlink(path)`, `unlinkat(fd, path, flags)` | `SYS_unlink` |
| Delete dir | `rmdir(path)` | `SYS_rmdir` |
| Rename/move | `rename(old, new)`, `renameat(...)` | `SYS_rename` |
| Truncate | `truncate(path, len)`, `ftruncate(fd, len)` | `SYS_truncate` |
| Open for write | `open(path, O_WRONLY\|O_TRUNC\|O_CREAT, ...)` | `SYS_open` |
| Chmod dangerous | `chmod(path, mode)` | `SYS_chmod` |

A single dylib intercepting these 6 symbol families covers the vast majority of filesystem destruction.

### What cannot be intercepted this way

1. **Direct syscalls** — code that calls `syscall(SYS_unlink, ...)` directly bypasses libc. Rare in Python/Node, but possible in C extensions.
2. **SIP-protected processes** — Apple's System Integrity Protection strips `DYLD_INSERT_LIBRARIES` for protected binaries (`/usr/bin/*`, `/System/*`). Claude Code is an Electron app installed to `/Applications/` — likely NOT SIP-protected, but needs verification.
3. **Spawned subprocesses** — `DYLD_INSERT_LIBRARIES` is inherited by child processes only if it remains in the environment. If Claude forks a shell that clears the environment, the child is unsandboxed.
4. **Network calls** — zero coverage. This is intentional — bashguard's hook layer covers network.

---

## Proposed Architecture

```
Claude Code process
│
├── DYLD_INSERT_LIBRARIES=libashguard_sandbox.dylib
│   │
│   ├── Intercepts: unlink, rmdir, rename, truncate, open(O_TRUNC)
│   │   │
│   │   ├── Path inside SANDBOX_ROOT?
│   │   │   └── Allow (write to working dir is fine)
│   │   │
│   │   ├── Path in PROTECTED_PATHS (/etc, ~/.ssh, ~/.aws, etc.)?
│   │   │   └── DENY → set errno=EPERM, return -1
│   │   │
│   │   └── Path outside SANDBOX_ROOT, not protected?
│   │       └── REDIRECT → rewrite to $SANDBOX_OVERLAY/path
│   │           (copy-on-write: original untouched, write goes to overlay)
│   │
│   └── All other calls: pass through to real libc
│
└── PreToolUse hook (existing bashguard hook layer)
    └── Semantic AST analysis (network, credentials, evasion, etc.)
```

Two layers, orthogonal coverage:
- **Hook layer**: semantic intent (what does this command *mean*)
- **Dylib layer**: filesystem enforcement (what does this command *do*)

---

## Implementation Spec

### Component 1: `libashguard_sandbox.dylib`

Written in C (not Python — must be a native dylib loadable by the dynamic linker).

```c
// bashguard_sandbox.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>

// Real libc functions, resolved at init
static int  (*real_unlink)(const char *path) = NULL;
static int  (*real_rmdir)(const char *path) = NULL;
static int  (*real_rename)(const char *old, const char *new) = NULL;
static int  (*real_truncate)(const char *path, off_t len) = NULL;
static int  (*real_open)(const char *path, int flags, ...) = NULL;

// Config from environment
static const char *sandbox_root = NULL;
static const char *overlay_dir  = NULL;

__attribute__((constructor))
static void sandbox_init(void) {
    real_unlink   = dlsym(RTLD_NEXT, "unlink");
    real_rmdir    = dlsym(RTLD_NEXT, "rmdir");
    real_rename   = dlsym(RTLD_NEXT, "rename");
    real_truncate = dlsym(RTLD_NEXT, "truncate");
    real_open     = dlsym(RTLD_NEXT, "open");

    sandbox_root = getenv("BASHGUARD_SANDBOX_ROOT");
    overlay_dir  = getenv("BASHGUARD_OVERLAY_DIR");
}

// Path classification
typedef enum { ALLOW, DENY, REDIRECT } policy_t;

static policy_t classify_path(const char *path) {
    // Protected paths: always deny writes
    static const char *protected[] = {
        "/etc/", "/usr/", "/bin/", "/sbin/", "/System/",
        "/Library/", "/private/etc/",
        NULL
    };
    // Home-relative protected dirs
    char ssh_path[PATH_MAX], aws_path[PATH_MAX];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(ssh_path, sizeof(ssh_path), "%s/.ssh", home);
        snprintf(aws_path, sizeof(aws_path), "%s/.aws", home);
    }

    for (int i = 0; protected[i]; i++) {
        if (strncmp(path, protected[i], strlen(protected[i])) == 0)
            return DENY;
    }
    if (home && strncmp(path, ssh_path, strlen(ssh_path)) == 0) return DENY;
    if (home && strncmp(path, aws_path, strlen(aws_path)) == 0) return DENY;

    // Sandbox root: allow (this is Claude's working dir)
    if (sandbox_root && strncmp(path, sandbox_root, strlen(sandbox_root)) == 0)
        return ALLOW;

    // Everything else outside sandbox: redirect to overlay
    if (overlay_dir) return REDIRECT;

    return ALLOW;  // No overlay configured: pass through
}

static void overlay_path(const char *path, char *out, size_t out_size) {
    snprintf(out, out_size, "%s%s", overlay_dir, path);
}

// Interposed symbols
int unlink(const char *path) {
    switch (classify_path(path)) {
        case DENY:     errno = EPERM; return -1;
        case REDIRECT: { char p[PATH_MAX]; overlay_path(path, p, sizeof(p));
                         return real_unlink(p); }
        default:       return real_unlink(path);
    }
}

int rmdir(const char *path) {
    switch (classify_path(path)) {
        case DENY:     errno = EPERM; return -1;
        case REDIRECT: { char p[PATH_MAX]; overlay_path(path, p, sizeof(p));
                         return real_rmdir(p); }
        default:       return real_rmdir(path);
    }
}

int rename(const char *old, const char *new) {
    // Deny if source is protected (can't move out of protected dir)
    // Deny if dest is protected (can't overwrite protected files)
    policy_t ps = classify_path(old);
    policy_t pd = classify_path(new);
    if (ps == DENY || pd == DENY) { errno = EPERM; return -1; }
    return real_rename(old, new);
}

int open(const char *path, int flags, ...) {
    // Only intercept destructive opens
    if (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_CREAT)) {
        switch (classify_path(path)) {
            case DENY: errno = EPERM; return -1;
            case REDIRECT: {
                char p[PATH_MAX]; overlay_path(path, p, sizeof(p));
                // ensure overlay parent dirs exist
                // ... mkdir -p logic ...
                return real_open(p, flags);
            }
            default: break;
        }
    }
    return real_open(path, flags);
}

int truncate(const char *path, off_t len) {
    switch (classify_path(path)) {
        case DENY:     errno = EPERM; return -1;
        case REDIRECT: { char p[PATH_MAX]; overlay_path(path, p, sizeof(p));
                         return real_truncate(p, len); }
        default:       return real_truncate(path, len);
    }
}
```

Build:
```bash
clang -dynamiclib -o libashguard_sandbox.dylib bashguard_sandbox.c \
    -install_name @rpath/libashguard_sandbox.dylib \
    -framework Security
```

### Component 2: `bashguard session` CLI subcommand

```
bashguard session start [--working-dir PATH]
bashguard session diff
bashguard session commit
bashguard session discard
bashguard session status
```

`start`:
1. Creates `~/.bashguard/sessions/<uuid>/overlay/` directory tree
2. Sets `BASHGUARD_SANDBOX_ROOT` to working dir
3. Sets `BASHGUARD_OVERLAY_DIR` to the overlay path
4. Emits shell exports for the user to `eval`: `eval $(bashguard session start)`

`diff`:
- Walks `overlay/` and shows what was written vs original
- Like `git diff` but for filesystem state

`commit`:
- Copies overlay writes back to real paths
- Archives the session

`discard`:
- Deletes the overlay — all agent writes vanish

### Component 3: Hook script (`hooks/70-bashguard`)

Extended to also verify the dylib is loaded when running in session mode:

```bash
#!/bin/bash
command -v bashguard >/dev/null 2>&1 || exit 0

# If session active, verify dylib is in env (warn if not)
if [ -n "$BASHGUARD_SESSION_ID" ] && [ -z "$DYLD_INSERT_LIBRARIES" ]; then
    echo '{"type":"warning","message":"bashguard session active but dylib not loaded — run: eval $(bashguard session start)"}' >&2
fi

exec bashguard hook
```

---

## Trade-off Analysis

### DYLD_INSERT_LIBRARIES vs. macFUSE

| Dimension | DYLD_INSERT_LIBRARIES | macFUSE |
|---|---|---|
| **Install friction** | Zero — env var only | High — kernel extension, System Preferences approval, reboot sometimes |
| **Coverage** | libc calls (Python, Node, bash all use libc) | All filesystem ops including direct syscalls |
| **Direct syscall bypass** | Vulnerable | Not vulnerable |
| **SIP-protected processes** | Stripped (blocked) | Works for all processes |
| **Subprocess inheritance** | Env-dependent | Automatic |
| **Performance** | Negligible (function pointer indirection) | Moderate (context switches to FUSE daemon) |
| **Stability** | Stable (libc ABI is stable) | Historically fragile on macOS upgrades |
| **Network isolation** | None | None |
| **CoW semantics** | Via overlay dir (manual) | Via overlayfs driver (automatic) |
| **Diff/rollback** | Manual (walk overlay dir) | Automatic (unmount = discard) |
| **macOS version req.** | Any | macFUSE 4.x requires macOS 10.15+ |
| **Works with Electron** | Yes (Electron is not SIP-protected) | Yes |
| **Works with system Python** | No (/usr/bin/python3 is SIP-protected) | Yes |

**Winner for zero-friction deploy: DYLD_INSERT_LIBRARIES**
**Winner for complete coverage: macFUSE**

### DYLD_INSERT_LIBRARIES vs. disk image mount

| Dimension | DYLD_INSERT_LIBRARIES | Disk image mount |
|---|---|---|
| **What it contains** | Any path the dylib intercepts | Only paths under the mount point |
| **Home dir writes** | Intercepted (redirect to overlay) | Only if home is inside mount |
| **Working dir writes** | Intercepted | Contained (writes go to image) |
| **Subprocess isolation** | Env-dependent | Strong (kernel enforces) |
| **Network** | None | None |
| **Setup** | `export DYLD_INSERT_LIBRARIES=...` | `hdiutil attach`, `cp -r`, `cd` |
| **Teardown** | Unset env var | `hdiutil detach` |
| **Diff** | Walk overlay dir | `hdiutil diff` (sparse) or custom |
| **Direct syscall bypass** | Yes | No |

**Winner for completeness within scope: disk image**
**Winner for arbitrary path protection: DYLD_INSERT_LIBRARIES**

### Combined architecture (recommended)

Use both:
- Disk image for working directory containment (strong, kernel-enforced)
- DYLD_INSERT_LIBRARIES for home dir / credential path protection (catches writes to ~/.ssh, ~/.aws, etc. that escape the working dir mount)
- bashguard hook layer for network, semantic intent, evasion detection

No single layer has full coverage. Three orthogonal layers together cover the main threat surface.

---

## SR&ED Experiment Design

**Project:** macOS Userspace Filesystem Interposition for AI Agent Containment

### Scientific Uncertainty

The key technical uncertainties that make this SR&ED-eligible:

1. **Coverage uncertainty:** What fraction of filesystem-destructive operations in Python/Node/bash processes route through interposable libc symbols vs. direct syscalls or alternative paths? No published measurement exists for the specific workload of AI coding agents.

2. **SIP boundary uncertainty:** Claude Code is an Electron app in `/Applications/`. Apple's SIP documentation does not specify whether third-party Electron apps in `/Applications/` are subject to `DYLD_INSERT_LIBRARIES` stripping. The actual behavior must be measured, not derived from documentation.

3. **Symbol family completeness:** The set of libc symbols that must be interposed to achieve complete write/delete coverage is not formally established. New symbols may be introduced in future macOS versions. The minimal complete set is unknown.

4. **Performance regression under load:** The overhead of path classification on every `open()` call across a busy Python process is not characterized. If classification adds >5% overhead, the approach is impractical.

### Hypothesis

H1: DYLD_INSERT_LIBRARIES interposition covering `unlink`, `rmdir`, `rename`, `truncate`, and `open(O_WRONLY|O_TRUNC)` achieves ≥95% coverage of filesystem-destructive operations performed by Python 3.11+ and Node.js 18+ processes on macOS 13+ running Claude Code.

H2: Claude Code's Electron runtime is not SIP-protected, allowing `DYLD_INSERT_LIBRARIES` injection.

H3: Path classification overhead on `open()` calls adds <2% CPU overhead to a representative Claude Code workload.

### Experiment 1: Coverage measurement

**Method:**
1. Instrument a macOS kernel (DTrace or ktrace) to record all `SYS_unlink`, `SYS_rmdir`, `SYS_rename`, `SYS_truncate`, `SYS_open` (write flags) syscalls from a test process.
2. Run a corpus of 50 AI-agent-generated bash scripts (destructive, edge-case-heavy) under instrumented Python and bash interpreters.
3. For each syscall, determine whether it originated from a libc call or a direct syscall via `syscall(2)`.
4. Measure: libc-routed / total = coverage fraction.

**Success criterion:** ≥95% of destructive syscalls are libc-routed.

**Tooling:**
```bash
# DTrace probe to capture unlink syscalls and their call stack
dtrace -n 'syscall::unlink:entry { @[execname, ustack()] = count(); }'
```

**Expected result:** Python's `os.unlink()`, `pathlib.Path.unlink()`, `shutil.rmtree()` all route through libc. Direct `ctypes.CDLL(None).syscall(...)` would bypass — expected to be rare in LLM-generated code.

### Experiment 2: SIP protection status of Claude Code

**Method:**
1. `codesign -dv --verbose=4 /Applications/Claude.app/Contents/MacOS/Claude`
2. Check for `com.apple.security.cs.allow-dyld-environment-variables` entitlement.
3. Empirically test: set `DYLD_INSERT_LIBRARIES` to a logging dylib, launch Claude Code, observe whether the dylib constructor fires.
4. Repeat for Claude Code's helper processes (Electron renderer, Node.js subprocess).

**Success criterion:** dylib constructor fires in main Claude Code process.

**Expected result:** Third-party Electron apps are not SIP-protected. Apple's documentation indicates SIP stripping only applies to `/usr/bin/`, `/usr/sbin/`, and system frameworks. Claude in `/Applications/` should be unprotected. This is an empirical verification, not a derivation.

### Experiment 3: Performance characterization

**Method:**
1. Baseline: run a standardized file-intensive workload (compile a medium Python project, run pytest suite) without the dylib.
2. Treatment: same workload with dylib loaded, path classification active.
3. Measure: wall time, CPU time, syscall count.
4. Repeat 10x, report mean and 95% CI.

**Workload:** `pytest` on bashguard's own test suite (380 tests, opens many files).

**Success criterion:** <2% overhead on wall time.

**Expected result:** Path classification is a string comparison against ~20 path prefixes, O(1) per call. Expected overhead is sub-millisecond per `open()` call. 380 tests × ~200 file opens/test = 76,000 `open()` calls. At 1µs overhead each = 76ms total. Baseline pytest run ~4s. Expected overhead ~2%.

### Experiment 4: Overlay coherence

**Method:**
1. Start a session with REDIRECT mode active (all writes outside sandbox_root go to overlay).
2. Run a script that writes, reads back, modifies, and deletes files across multiple paths.
3. Verify: reads after writes return correct data (overlay is consulted), deletes in overlay don't affect originals, reads of unmodified files return original data.
4. Commit the overlay and verify originals are correctly updated.

**Success criterion:** All read-after-write operations return correct data; originals unchanged until explicit commit.

**Known hard case:** `rename()` across overlay/real boundary (source in overlay, dest in real or vice versa) requires special handling — cannot use real `rename()` across filesystems. Must copy + delete.

### SR&ED Eligibility Rationale

This work constitutes SR&ED under CRA guidelines because:

1. **Technological uncertainty exists:** The coverage fraction, SIP status, and performance characteristics cannot be determined without experimentation. Existing literature covers DYLD interposition in general but not for AI agent workloads on modern macOS versions.

2. **Systematic investigation:** The experiments follow controlled methodology with quantified success criteria, not trial-and-error.

3. **Technological advancement:** If successful, this produces a novel technique for userspace AI agent containment on macOS without kernel extensions — an advance over the current state of the art (jai, which requires Linux; macFUSE, which requires kernel extension approval).

4. **Not commercial development:** The research uncertainty must be resolved before the feature can be built. Experiment 2 in particular (SIP status) has a binary unknown outcome — if Claude Code is SIP-protected, the entire approach fails and macFUSE becomes mandatory.

---

## Open Questions

1. Does Electron's Node.js subprocess inherit `DYLD_INSERT_LIBRARIES`? Node may clear the environment before spawning bash.
2. Does the `unlinkat()` family need separate interposition? Linux agents use `unlinkat` heavily; macOS behavior differs.
3. Python's `os.remove()` on macOS — does it use `unlink()` or `unlinkat(AT_FDCWD, ...)`? Need to verify with `nm` or DTrace.
4. What happens when the overlay filesystem fills up? Need graceful degradation (fall through to real path or deny).

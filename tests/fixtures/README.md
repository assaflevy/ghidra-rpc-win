# tests/fixtures

This directory holds static test artifacts committed to the repository so the
integration-test suite is fully self-contained and reproducible.

## testapp — the integration-test binary

`testapp` is a small x86-64 ELF executable compiled from `testapp.c`.  It
provides a handful of user-defined functions that exercise libc imports
(malloc, free, printf, strlen, …) and contains string literals used by the
test-suite's string-search assertions.

**Rebuild** (requires GCC on an x86-64 Linux host):

```sh
gcc -O0 -m64 -o tests/fixtures/testapp tests/fixtures/testapp.c
```

The binary is kept in git so no compiler toolchain is needed to run the tests.

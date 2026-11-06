/* SPDX-FileCopyrightText: 2026 Arteractive LLC
 * SPDX-License-Identifier: Apache-2.0
 * Optional native fault tests, not a cryptographic implementation test.
 */
#define main worker_entry_for_tests
#include "openssl_worker.c"
#undef main

static int failures = 0, checks = 0;

static void expect(const char *label, int actual, int expected)
{
    ++checks;
    if (actual != expected) {
        fprintf(stderr, "%s: got %d, expected %d\n", label, actual, expected);
        ++failures;
    }
}

int main(void)
{
    ERR_clear_error();
    expect("empty queue, no length rejection", rejected_input(0), 90);
    expect("empty queue, backend rejected wrong ciphertext size", rejected_input(1), 2);
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
    expect("known invalid key", rejected_input(0), 2);
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
    expect("known invalid key length", rejected_input(0), 2);
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
    expect("known invalid seed length", rejected_input(0), 2);
    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    expect("malloc failure even with wrong input length", rejected_input(1), 90);
    ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
    expect("internal failure", rejected_input(0), 90);
    ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
    expect("unknown provider reason", rejected_input(1), 90);
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    expect("mixed known and internal errors", rejected_input(0), 90);
    expect("error queue drained", ERR_peek_error() != 0, 0);
    printf("Native error classifier: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

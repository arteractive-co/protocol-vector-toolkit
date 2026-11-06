/* SPDX-FileCopyrightText: 2026 Arteractive LLC
 * SPDX-License-Identifier: Apache-2.0
 * Test-only EVP wrapper. AS IS. Never use with production secrets.
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <stdio.h>
#include <string.h>

/* Two big-endian length-prefixed opaque blobs. Framing is not ML-KEM
 * serialization and never reverses or normalizes the supplied key bytes. */
static int read_blob(unsigned char *buf, size_t cap, size_t *n)
{
    unsigned char h[4];
    if (fread(h, 1, 4, stdin) != 4) return 0;
    *n = ((size_t)h[0] << 24) | ((size_t)h[1] << 16) | ((size_t)h[2] << 8) | h[3];
    return *n <= cap && fread(buf, 1, *n, stdin) == *n;
}

static int write_blob(const unsigned char *buf, size_t n)
{
    unsigned char h[4] = {(unsigned char)(n >> 24), (unsigned char)(n >> 16),
                           (unsigned char)(n >> 8), (unsigned char)n};
    return fwrite(h, 1, 4, stdout) == 4 && fwrite(buf, 1, n, stdout) == n;
}

/* Fail closed on unknown/backend setup/internal errors. An empty error queue
 * is allowed only after decapsulation itself rejects a wrong ciphertext size.
 * Do not pre-reject in the wrapper: a backend accepting that input must fail
 * the vector comparison, not be hidden by our own validation. */
static int rejected_input(int allow_empty)
{
    unsigned long error;
    int seen = 0, known = 1;
    while ((error = ERR_get_error()) != 0) {
        int reason = ERR_GET_REASON(error);
        seen = 1;
        if (ERR_GET_LIB(error) != ERR_LIB_PROV ||
                (reason != PROV_R_INVALID_KEY && reason != PROV_R_INVALID_KEY_LENGTH &&
                 reason != PROV_R_INVALID_SEED_LENGTH)) known = 0;
    }
    return known && (seen || allow_empty) ? 2 : 90;
}

int main(int argc, char **argv)
{
    unsigned char a[8192], b[8192], first[8192], second[8192];
    size_t an, bn, fn = sizeof(first), sn = sizeof(second);
    EVP_PKEY_CTX *import = NULL, *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2], kem_params[2];
    const char *field;
    int selection, rc = 90, encaps, keygen;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(OpenSSL_version(OPENSSL_VERSION)); return 0;
    }
    if (argc != 3 || (strcmp(argv[1], "ML-KEM-512") != 0 &&
            strcmp(argv[1], "ML-KEM-768") != 0 && strcmp(argv[1], "ML-KEM-1024") != 0))
        return 90;
    encaps = strcmp(argv[2], "encaps") == 0;
    keygen = strcmp(argv[2], "keygen") == 0;
    if (!encaps && !keygen && strcmp(argv[2], "seed-decaps") != 0 &&
            strcmp(argv[2], "expanded-decaps") != 0) return 90;
    if (!read_blob(a, sizeof(a), &an) || !read_blob(b, sizeof(b), &bn) || getchar() != EOF)
        return 90;
    field = encaps ? OSSL_PKEY_PARAM_PUB_KEY :
        (strcmp(argv[2], "expanded-decaps") == 0 ? OSSL_PKEY_PARAM_PRIV_KEY :
         OSSL_PKEY_PARAM_ML_KEM_SEED);
    selection = encaps ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR;
    import = EVP_PKEY_CTX_new_from_name(NULL, argv[1], "provider=default");
    if (import == NULL || EVP_PKEY_fromdata_init(import) <= 0) goto done;
    params[0] = OSSL_PARAM_construct_octet_string(field, a, an);
    params[1] = OSSL_PARAM_construct_end();
    ERR_clear_error();
    if (EVP_PKEY_fromdata(import, &key, selection, params) <= 0) {
        rc = rejected_input(0); goto done;
    }
    if (keygen) {
        if (bn != 0) goto done;
        if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, first, sizeof(first), &fn) <= 0 ||
                EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, second, sizeof(second), &sn) <= 0)
            goto done;
    } else {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default");
        if (ctx == NULL) goto done;
        if (encaps) {
            kem_params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, b, bn);
            kem_params[1] = OSSL_PARAM_construct_end();
            if (EVP_PKEY_encapsulate_init(ctx, kem_params) <= 0) goto done;
            ERR_clear_error();
            if (EVP_PKEY_encapsulate(ctx, first, &fn, second, &sn) <= 0) {
                rc = rejected_input(0); goto done;
            }
        } else {
            if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto done;
            ERR_clear_error();
            if (EVP_PKEY_decapsulate(ctx, first, &fn, b, bn) <= 0) {
                size_t ct_size = strcmp(argv[1], "ML-KEM-512") == 0 ? 768 :
                    (strcmp(argv[1], "ML-KEM-768") == 0 ? 1088 : 1568);
                rc = rejected_input(bn != ct_size); goto done;
            }
            if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, second, sizeof(second), &sn) <= 0)
                goto done;
        }
    }
    if (fn > sizeof(first) || sn > sizeof(second)) goto done;
    if (write_blob(first, fn) && write_blob(second, sn) && fflush(stdout) == 0) rc = 0;
done:
    if (rc != 0) ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(import);
    OPENSSL_cleanse(a, sizeof(a)); OPENSSL_cleanse(b, sizeof(b));
    OPENSSL_cleanse(first, sizeof(first)); OPENSSL_cleanse(second, sizeof(second));
    return rc;
}

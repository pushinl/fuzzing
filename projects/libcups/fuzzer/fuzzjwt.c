/*
 * JWT Token Fuzzer for libcups
 *
 * This fuzzer tests JWT token parsing, creation, signing, and verification
 * functionality in the libcups library.
 *
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include "cups.h"
#include "jwt.h"
#include "json.h"

// Parse input data into segments
static int parse_jwt_segments(const uint8_t *data, size_t size,
                              const uint8_t **segments, size_t *seg_sizes, int max_segments)
{
    if (size < 4)
        return 0;

    uint32_t num_segments = *(uint32_t *)data % max_segments + 1;
    data += 4;
    size -= 4;

    size_t pos = 0;
    int count = 0;

    for (uint32_t i = 0; i < num_segments && count < max_segments && pos < size; i++)
    {
        if (pos + 2 >= size)
            break;

        uint16_t seg_len = *(uint16_t *)(data + pos) % (size - pos - 2) + 1;
        pos += 2;

        if (pos + seg_len <= size)
        {
            segments[count] = data + pos;
            seg_sizes[count] = seg_len;
            count++;
            pos += seg_len;
        }
    }

    return count;
}

// Create test JWT string from input data
static char *create_test_jwt(const uint8_t *data, size_t size)
{
    if (size == 0)
        return NULL;

    char *jwt_str = malloc(size + 1);
    if (!jwt_str)
        return NULL;

    memcpy(jwt_str, data, size);
    jwt_str[size] = '\0';

    // Basic sanitization for printable characters
    for (size_t i = 0; i < size; i++)
    {
        if (jwt_str[i] == '\0')
        {
            jwt_str[i] = '.';
        }
    }

    return jwt_str;
}

// Test JWT import and basic operations
static void test_jwt_import_operations(const char *jwt_str)
{
    if (!jwt_str)
        return;

    cups_jwt_t *jwt = NULL;
    char *exported_str = NULL;

    // Test cupsJWTImportString
    jwt = cupsJWTImportString(jwt_str);
    if (jwt)
    {
        // Test cupsJWTGetAlgorithm
        cups_jwa_t alg = cupsJWTGetAlgorithm(jwt);
        (void)alg;

        // Test cupsJWTGetHeaders
        cups_json_t *headers = cupsJWTGetHeaders(jwt);
        if (headers)
        {
            // Test header access
            const char *header_keys[] = {"alg", "typ", "kid", "x5t"};
            for (int i = 0; i < 4; i++)
            {
                cups_jtype_t type = cupsJWTGetHeaderType(jwt, header_keys[i]);
                (void)type;

                const char *str_val = cupsJWTGetHeaderString(jwt, header_keys[i]);
                (void)str_val;

                double num_val = cupsJWTGetHeaderNumber(jwt, header_keys[i]);
                (void)num_val;
            }
        }

        // Test cupsJWTGetClaims
        cups_json_t *claims = cupsJWTGetClaims(jwt);
        if (claims)
        {
            // Test claim access
            const char *claim_keys[] = {"iss", "sub", "aud", "exp", "iat", "nbf", "jti"};
            for (int i = 0; i < 7; i++)
            {
                cups_jtype_t type = cupsJWTGetClaimType(jwt, claim_keys[i]);
                (void)type;

                const char *str_val = cupsJWTGetClaimString(jwt, claim_keys[i]);
                (void)str_val;

                double num_val = cupsJWTGetClaimNumber(jwt, claim_keys[i]);
                (void)num_val;
            }
        }

        // Test cupsJWTExportString
        exported_str = cupsJWTExportString(jwt);
        if (exported_str)
        {
            // Test re-importing exported JWT
            cups_jwt_t *reimported = cupsJWTImportString(exported_str);
            if (reimported)
            {
                cupsJWTDelete(reimported);
            }
            free(exported_str);
        }

        cupsJWTDelete(jwt);
    }
}

// Test JWT creation and manipulation
static void test_jwt_creation(const uint8_t *data, size_t size)
{
    if (size < 32)
        return;

    cups_jwt_t *jwt = cupsJWTNew(NULL, NULL);
    if (!jwt)
        return;

    // Set various claims based on input data
    size_t pos = 0;

    // Set issuer
    if (pos + 16 < size)
    {
        char issuer[64];
        snprintf(issuer, sizeof(issuer), "issuer_%d", data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimString(jwt, CUPS_JWT_ISS, issuer);
        pos += 2;
    }

    // Set subject
    if (pos + 16 < size)
    {
        char subject[64];
        snprintf(subject, sizeof(subject), "subject_%d", data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimString(jwt, CUPS_JWT_SUB, subject);
        pos += 2;
    }

    // Set audience
    if (pos + 16 < size)
    {
        char audience[64];
        snprintf(audience, sizeof(audience), "audience_%d", data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimString(jwt, CUPS_JWT_AUD, audience);
        pos += 2;
    }

    // Set expiration time
    if (pos + 8 < size)
    {
        double exp_time = time(NULL) + (data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimNumber(jwt, CUPS_JWT_EXP, exp_time);
        pos += 2;
    }

    // Set issued at time
    if (pos + 8 < size)
    {
        double iat_time = time(NULL) - (data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimNumber(jwt, CUPS_JWT_IAT, iat_time);
        pos += 2;
    }

    // Set not before time
    if (pos + 8 < size)
    {
        double nbf_time = time(NULL) - (data[pos] | (data[pos + 1] << 8));
        cupsJWTSetClaimNumber(jwt, CUPS_JWT_NBF, nbf_time);
        pos += 2;
    }

    // Test signing with different algorithms
    cups_jwa_t algorithms[] = {CUPS_JWA_HS256, CUPS_JWA_HS384, CUPS_JWA_HS512};

    for (int i = 0; i < 3; i++)
    {
        // Generate a key for this algorithm
        cups_json_t *key = cupsJWTMakePrivateKey(algorithms[i]);
        if (key)
        {
            // Test signing
            bool signed_ok = cupsJWTSign(jwt, algorithms[i], key);
            if (signed_ok)
            {
                // Test signature verification
                bool valid = cupsJWTHasValidSignature(jwt, key);
                (void)valid;

                // Test export after signing
                char *signed_jwt = cupsJWTExportString(jwt);
                if (signed_jwt)
                {
                    // Test importing signed JWT
                    test_jwt_import_operations(signed_jwt);
                    free(signed_jwt);
                }
            }

            cupsJSONDelete(key);
        }
    }

    cupsJWTDelete(jwt);
}

// Test asymmetric algorithms if data is sufficient
static void test_jwt_asymmetric(const uint8_t *data, size_t size)
{
    if (size < 64)
        return;

    cups_jwt_t *jwt = cupsJWTNew(NULL, NULL);
    if (!jwt)
        return;

    // Set basic claims
    cupsJWTSetClaimString(jwt, CUPS_JWT_ISS, "test_issuer");
    cupsJWTSetClaimString(jwt, CUPS_JWT_SUB, "test_subject");
    cupsJWTSetClaimNumber(jwt, CUPS_JWT_EXP, time(NULL) + 3600);

    // Test RSA algorithms
    cups_jwa_t rsa_algorithms[] = {CUPS_JWA_RS256, CUPS_JWA_RS384, CUPS_JWA_RS512};

    for (int i = 0; i < 3 && (i * 20) < size; i++)
    {
        cups_json_t *private_key = cupsJWTMakePrivateKey(rsa_algorithms[i]);
        if (private_key)
        {
            cups_json_t *public_key = cupsJWTMakePublicKey(private_key);
            if (public_key)
            {
                // Test signing with private key
                bool signed_ok = cupsJWTSign(jwt, rsa_algorithms[i], private_key);
                if (signed_ok)
                {
                    // Test verification with public key
                    bool valid = cupsJWTHasValidSignature(jwt, public_key);
                    (void)valid;

                    // Test export and re-import
                    char *jwt_str = cupsJWTExportString(jwt);
                    if (jwt_str)
                    {
                        cups_jwt_t *imported = cupsJWTImportString(jwt_str);
                        if (imported)
                        {
                            // Verify imported JWT
                            bool imported_valid = cupsJWTHasValidSignature(imported, public_key);
                            (void)imported_valid;
                            cupsJWTDelete(imported);
                        }
                        free(jwt_str);
                    }
                }

                cupsJSONDelete(public_key);
            }
            cupsJSONDelete(private_key);
        }
    }

    // Test ECDSA algorithms
    if (size >= 80)
    {
        cups_jwa_t ec_algorithms[] = {CUPS_JWA_ES256, CUPS_JWA_ES384, CUPS_JWA_ES512};

        for (int i = 0; i < 3 && (i * 20 + 60) < size; i++)
        {
            cups_json_t *private_key = cupsJWTMakePrivateKey(ec_algorithms[i]);
            if (private_key)
            {
                cups_json_t *public_key = cupsJWTMakePublicKey(private_key);
                if (public_key)
                {
                    bool signed_ok = cupsJWTSign(jwt, ec_algorithms[i], private_key);
                    if (signed_ok)
                    {
                        bool valid = cupsJWTHasValidSignature(jwt, public_key);
                        (void)valid;
                    }
                    cupsJSONDelete(public_key);
                }
                cupsJSONDelete(private_key);
            }
        }
    }

    cupsJWTDelete(jwt);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
    {
        return 0;
    }

    const uint8_t *segments[6];
    size_t seg_sizes[6];
    int num_segments = parse_jwt_segments(data, size, segments, seg_sizes, 6);

    // Test 1: Direct JWT string parsing
    for (int i = 0; i < num_segments; i++)
    {
        char *jwt_str = create_test_jwt(segments[i], seg_sizes[i]);
        if (jwt_str)
        {
            test_jwt_import_operations(jwt_str);
            free(jwt_str);
        }
    }

    // Test 2: JWT creation and manipulation
    test_jwt_creation(data, size);

    // Test 3: Asymmetric algorithms (more resource intensive)
    if (size >= 64)
    {
        test_jwt_asymmetric(data, size);
    }

    return 0;
}
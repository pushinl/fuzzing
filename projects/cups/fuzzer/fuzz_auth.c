/*
 * Authentication Functions Fuzzer for CUPS
 *
 * This fuzzer tests authentication functionality including scheme parsing,
 * WWW-Authenticate header processing, and authentication string construction.
 *
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "cups.h"
#include "http.h"
#include "cups-private.h"

// Global variables for cleanup
static http_t *g_test_http = NULL;

// Cleanup function
static void cleanup_auth_resources(void)
{
    if (g_test_http)
    {
        httpClose(g_test_http);
        g_test_http = NULL;
    }
}

// Parse input data into segments for authentication testing
static int parse_auth_segments(const uint8_t *data, size_t size,
                               const uint8_t **segments, size_t *seg_sizes, int max_segments)
{
    if (size < 4)
        return 0;

    uint32_t num_segments = *(uint32_t *)data;
    if (num_segments == 0 || num_segments > max_segments)
        return 0;

    const uint8_t *ptr = data + 4;
    size_t remaining = size - 4;

    for (uint32_t i = 0; i < num_segments && i < max_segments; i++)
    {
        if (remaining < 4)
            return i;

        uint32_t seg_len = *(uint32_t *)ptr;
        ptr += 4;
        remaining -= 4;

        if (seg_len > remaining)
            return i;

        segments[i] = ptr;
        seg_sizes[i] = seg_len;
        ptr += seg_len;
        remaining -= seg_len;
    }

    return num_segments;
}

// Create a mock HTTP connection for authentication testing
static http_t *create_mock_http_connection(void)
{
    // Create a mock HTTP connection - we'll use a localhost connection
    // that doesn't actually connect but provides the structure needed
    http_t *http = NULL;

    // Initialize HTTP subsystem
    httpInitialize();

    // Try to create a local connection for testing
    // This may fail but that's okay for fuzzing purposes
    http = httpConnect2("localhost", 80, NULL, AF_UNSPEC, HTTP_ENCRYPTION_NEVER,
                        1, 1000, NULL);

    return http; // May be NULL, which is fine for testing
}

// Test authentication scheme parsing
static void test_auth_scheme_parsing(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 1 || seg_sizes[0] == 0)
        return;

    // Create WWW-Authenticate header data
    char www_auth_header[1024];
    size_t copy_len = seg_sizes[0] < sizeof(www_auth_header) - 1 ? seg_sizes[0] : sizeof(www_auth_header) - 1;
    memcpy(www_auth_header, segments[0], copy_len);
    www_auth_header[copy_len] = '\0';

    // Ensure printable characters to avoid issues
    for (size_t i = 0; i < copy_len; i++)
    {
        if (www_auth_header[i] < 32 || www_auth_header[i] > 126)
        {
            www_auth_header[i] = ' ';
        }
    }

    // Create a mock HTTP connection for testing
    if (!g_test_http)
    {
        g_test_http = create_mock_http_connection();
    }

    if (g_test_http)
    {
        // Set the WWW-Authenticate header
        httpSetField(g_test_http, HTTP_FIELD_WWW_AUTHENTICATE, www_auth_header);

        // Test getting the field back
        const char *auth_field = httpGetField(g_test_http, HTTP_FIELD_WWW_AUTHENTICATE);
        (void)auth_field; // Suppress unused variable warning

        // Test various authentication methods if available
        const char *methods[] = {"Basic", "Digest", "Negotiate", "Bearer"};
        for (int i = 0; i < 4; i++)
        {
            // Test if the method is in the header
            if (strstr(www_auth_header, methods[i]))
            {
                // Found a method, could do additional testing here
            }
        }
    }
}

// Test authentication string construction
static void test_auth_string_construction(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 2)
        return;

    char scheme[64] = "Basic";
    char auth_data[512];

    if (seg_sizes[1] > 0)
    {
        size_t copy_len = seg_sizes[1] < sizeof(auth_data) - 1 ? seg_sizes[1] : sizeof(auth_data) - 1;
        memcpy(auth_data, segments[1], copy_len);
        auth_data[copy_len] = '\0';

        // Clean the data
        for (size_t i = 0; i < copy_len; i++)
        {
            if (auth_data[i] < 32 || auth_data[i] > 126)
            {
                auth_data[i] = 'A';
            }
        }
    }
    else
    {
        strcpy(auth_data, "testdata");
    }

    if (g_test_http)
    {
        // Test httpSetAuthString
        httpSetAuthString(g_test_http, scheme, auth_data);

        // Test httpGetAuthString
        char *current_auth = httpGetAuthString(g_test_http);
        (void)current_auth; // Suppress unused variable warning

        // Clear auth string
        httpSetAuthString(g_test_http, NULL, NULL);
    }
}

// Test basic authentication scenarios
static void test_basic_auth_scenarios(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 3)
        return;

    char username[128] = "testuser";
    char password[128] = "testpass";

    // Extract username from segment
    if (seg_sizes[2] > 0)
    {
        size_t copy_len = seg_sizes[2] < sizeof(username) - 1 ? seg_sizes[2] : sizeof(username) - 1;
        memcpy(username, segments[2], copy_len);
        username[copy_len] = '\0';

        // Clean username
        for (size_t i = 0; i < copy_len; i++)
        {
            if (username[i] < 32 || username[i] > 126 || username[i] == ':')
            {
                username[i] = 'u';
            }
        }
    }

    // Extract password from segment if available
    if (num_segments > 3 && seg_sizes[3] > 0)
    {
        size_t copy_len = seg_sizes[3] < sizeof(password) - 1 ? seg_sizes[3] : sizeof(password) - 1;
        memcpy(password, segments[3], copy_len);
        password[copy_len] = '\0';

        // Clean password
        for (size_t i = 0; i < copy_len; i++)
        {
            if (password[i] < 32 || password[i] > 126)
            {
                password[i] = 'p';
            }
        }
    }

    // Create Basic auth string manually
    char user_pass[256];
    char encoded_auth[512];

    snprintf(user_pass, sizeof(user_pass), "%s:%s", username, password);

    // Test base64 encoding for Basic auth
    httpEncode64_2(encoded_auth, sizeof(encoded_auth), user_pass, strlen(user_pass));

    char basic_auth[600];
    snprintf(basic_auth, sizeof(basic_auth), "Basic %s", encoded_auth);

    if (g_test_http)
    {
        httpSetAuthString(g_test_http, "Basic", encoded_auth);
    }
}

// Test digest authentication components
static void test_digest_auth_components(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 4)
        return;

    // Create mock digest challenge components
    char realm[128] = "Test Realm";
    char nonce[256] = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    char method[16] = "GET";
    char uri[256] = "/test";

    if (seg_sizes[4] > 0)
    {
        size_t copy_len = seg_sizes[4] < sizeof(realm) - 1 ? seg_sizes[4] : sizeof(realm) - 1;
        memcpy(realm, segments[4], copy_len);
        realm[copy_len] = '\0';

        // Clean realm
        for (size_t i = 0; i < copy_len; i++)
        {
            if (realm[i] < 32 || realm[i] > 126 || realm[i] == '"')
            {
                realm[i] = 'R';
            }
        }
    }

    // Construct digest challenge header
    char digest_challenge[1024];
    snprintf(digest_challenge, sizeof(digest_challenge),
             "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"",
             realm, nonce);

    if (g_test_http)
    {
        httpSetField(g_test_http, HTTP_FIELD_WWW_AUTHENTICATE, digest_challenge);

        // Test parsing the digest challenge
        const char *challenge = httpGetField(g_test_http, HTTP_FIELD_WWW_AUTHENTICATE);
        (void)challenge;

        // Test digest response construction (simplified)
        char digest_response[1024];
        snprintf(digest_response, sizeof(digest_response),
                 "Digest username=\"testuser\", realm=\"%s\", nonce=\"%s\", "
                 "uri=\"%s\", response=\"6629fae49393a05397450978507c4ef1\"",
                 realm, nonce, uri);
    }
}

// Test authentication error handling
static void test_auth_error_handling(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 5)
        return;

    // Test with malformed authentication data
    char malformed_data[256];
    if (seg_sizes[5] > 0)
    {
        size_t copy_len = seg_sizes[5] < sizeof(malformed_data) - 1 ? seg_sizes[5] : sizeof(malformed_data) - 1;
        memcpy(malformed_data, segments[5], copy_len);
        malformed_data[copy_len] = '\0';
    }
    else
    {
        strcpy(malformed_data, "malformed");
    }

    if (g_test_http)
    {
        // Test with various malformed auth strings
        httpSetAuthString(g_test_http, "", malformed_data);
        httpSetAuthString(g_test_http, "Unknown", malformed_data);
        httpSetAuthString(g_test_http, NULL, malformed_data);
        httpSetAuthString(g_test_http, "Basic", NULL);

        // Test cupsDoAuthentication with mock data
        // Note: This will likely fail but should not crash
        cupsDoAuthentication(g_test_http, "GET", "/test");

        // Reset
        httpSetAuthString(g_test_http, NULL, NULL);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Minimum size check
    if (size < 30)
    {
        return 0;
    }

    // Setup cleanup
    atexit(cleanup_auth_resources);

    // Parse input segments
    const uint8_t *segments[10];
    size_t seg_sizes[10];
    int num_segments = parse_auth_segments(data, size, segments, seg_sizes, 10);

    if (num_segments < 1)
    {
        return 0;
    }

    // Initialize HTTP for authentication testing
    httpInitialize();

    // Create mock HTTP connection if needed
    if (!g_test_http)
    {
        g_test_http = create_mock_http_connection();
    }

    // Test various authentication functionality
    test_auth_scheme_parsing(segments, seg_sizes, num_segments);
    test_auth_string_construction(segments, seg_sizes, num_segments);
    test_basic_auth_scenarios(segments, seg_sizes, num_segments);
    test_digest_auth_components(segments, seg_sizes, num_segments);
    test_auth_error_handling(segments, seg_sizes, num_segments);

    // Cleanup for this iteration
    if (g_test_http)
    {
        httpClose(g_test_http);
        g_test_http = NULL;
    }

    return 0;
}
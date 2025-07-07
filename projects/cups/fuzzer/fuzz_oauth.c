/*
 * OAuth Functions Fuzzer for CUPS
 *
 * This fuzzer tests OAuth 2.0 functionality including token management,
 * authorization flows, JSON processing, and metadata handling.
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
#include "oauth.h"
#include "json.h"
#include "cups-private.h"

// Global variables for cleanup
static char *g_temp_auth_uri = NULL;
static char *g_temp_resource_uri = NULL;

// Cleanup function
static void cleanup_oauth_resources(void)
{
    if (g_temp_auth_uri)
    {
        // Clear any cached tokens
        cupsOAuthClearTokens(g_temp_auth_uri, g_temp_resource_uri);
        free(g_temp_auth_uri);
        g_temp_auth_uri = NULL;
    }
    if (g_temp_resource_uri)
    {
        free(g_temp_resource_uri);
        g_temp_resource_uri = NULL;
    }
}

// Parse input data into segments for OAuth testing
static int parse_oauth_segments(const uint8_t *data, size_t size,
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

// Create safe OAuth URIs for testing
static void create_test_oauth_uris(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    char auth_base[256] = "https://example.com/oauth";
    char resource_base[256] = "https://api.example.com";

    // Customize auth URI if we have segment data
    if (num_segments > 0 && seg_sizes[0] > 0)
    {
        char custom_suffix[128];
        size_t copy_len = seg_sizes[0] < sizeof(custom_suffix) - 1 ? seg_sizes[0] : sizeof(custom_suffix) - 1;
        memcpy(custom_suffix, segments[0], copy_len);
        custom_suffix[copy_len] = '\0';

        // Clean the suffix to be URL-safe
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(custom_suffix[i]) && custom_suffix[i] != '-' && custom_suffix[i] != '_')
            {
                custom_suffix[i] = 'a';
            }
        }

        snprintf(auth_base, sizeof(auth_base), "https://auth%s.example.com/oauth", custom_suffix);
    }

    // Customize resource URI if we have segment data
    if (num_segments > 1 && seg_sizes[1] > 0)
    {
        char custom_resource[128];
        size_t copy_len = seg_sizes[1] < sizeof(custom_resource) - 1 ? seg_sizes[1] : sizeof(custom_resource) - 1;
        memcpy(custom_resource, segments[1], copy_len);
        custom_resource[copy_len] = '\0';

        // Clean the resource path
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(custom_resource[i]) && custom_resource[i] != '/' && custom_resource[i] != '-')
            {
                custom_resource[i] = 'r';
            }
        }

        snprintf(resource_base, sizeof(resource_base), "https://api.example.com/%s", custom_resource);
    }

    // Allocate and store URIs
    g_temp_auth_uri = strdup(auth_base);
    g_temp_resource_uri = strdup(resource_base);
}

// Test OAuth token operations
static void test_oauth_token_operations(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (!g_temp_auth_uri || !g_temp_resource_uri)
        return;

    char access_token[512] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoidG9rZW4ifQ";
    char user_id[256] = "test_user_123";
    char refresh_token[512] = "refresh_token_example_123456789";
    time_t expires = time(NULL) + 3600; // 1 hour from now

    // Customize tokens with fuzz data
    if (num_segments > 2 && seg_sizes[2] > 0)
    {
        size_t copy_len = seg_sizes[2] < sizeof(access_token) - 1 ? seg_sizes[2] : sizeof(access_token) - 1;
        memcpy(access_token, segments[2], copy_len);
        access_token[copy_len] = '\0';

        // Ensure token is base64url-safe
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(access_token[i]) && access_token[i] != '-' &&
                access_token[i] != '_' && access_token[i] != '.')
            {
                access_token[i] = 'A';
            }
        }
    }

    if (num_segments > 3 && seg_sizes[3] > 0)
    {
        size_t copy_len = seg_sizes[3] < sizeof(user_id) - 1 ? seg_sizes[3] : sizeof(user_id) - 1;
        memcpy(user_id, segments[3], copy_len);
        user_id[copy_len] = '\0';

        // Clean user ID
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(user_id[i]) && user_id[i] != '_' && user_id[i] != '-')
            {
                user_id[i] = 'u';
            }
        }
    }

    // Test cupsOAuthSaveTokens
    cupsOAuthSaveTokens(g_temp_auth_uri, g_temp_resource_uri,
                        access_token, expires, user_id, refresh_token);

    // Test cupsOAuthCopyAccessToken
    char *retrieved_access = cupsOAuthCopyAccessToken(g_temp_auth_uri, g_temp_resource_uri, NULL);
    if (retrieved_access)
    {
        free(retrieved_access);
    }

    // Test cupsOAuthCopyRefreshToken
    char *retrieved_refresh = cupsOAuthCopyRefreshToken(g_temp_auth_uri, g_temp_resource_uri);
    if (retrieved_refresh)
    {
        free(retrieved_refresh);
    }

    // Test cupsOAuthCopyUserID
    char *retrieved_user = cupsOAuthCopyUserID(g_temp_auth_uri, g_temp_resource_uri);
    if (retrieved_user)
    {
        free(retrieved_user);
    }
}

// Test OAuth client data operations
static void test_oauth_client_data(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (!g_temp_auth_uri)
        return;

    char client_id[256] = "test_client_id_12345";
    char client_secret[512] = "test_client_secret_abcdef";
    char redirect_uri[512] = "http://localhost:8080/callback";

    // Customize client data with fuzz input
    if (num_segments > 4 && seg_sizes[4] > 0)
    {
        size_t copy_len = seg_sizes[4] < sizeof(client_id) - 1 ? seg_sizes[4] : sizeof(client_id) - 1;
        memcpy(client_id, segments[4], copy_len);
        client_id[copy_len] = '\0';

        // Clean client ID
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(client_id[i]) && client_id[i] != '-' && client_id[i] != '_')
            {
                client_id[i] = 'c';
            }
        }
    }

    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        size_t copy_len = seg_sizes[5] < sizeof(client_secret) - 1 ? seg_sizes[5] : sizeof(client_secret) - 1;
        memcpy(client_secret, segments[5], copy_len);
        client_secret[copy_len] = '\0';

        // Clean client secret
        for (size_t i = 0; i < copy_len; i++)
        {
            if (client_secret[i] < 32 || client_secret[i] > 126)
            {
                client_secret[i] = 's';
            }
        }
    }

    // Test cupsOAuthSaveClientData
    cupsOAuthSaveClientData(g_temp_auth_uri, redirect_uri, client_id, client_secret);

    // Test cupsOAuthCopyClientID
    char *retrieved_id = cupsOAuthCopyClientID(g_temp_auth_uri, redirect_uri);
    if (retrieved_id)
    {
        free(retrieved_id);
    }

    // Test clearing client data
    cupsOAuthSaveClientData(g_temp_auth_uri, redirect_uri, NULL, NULL);
}

// Test OAuth authorization metadata
static void test_oauth_metadata_operations(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (!g_temp_auth_uri)
        return;

    // Test cupsOAuthCopyMetadata
    cups_json_t *metadata = cupsOAuthCopyMetadata(g_temp_auth_uri);

    if (metadata)
    {
        // Test various metadata access functions
        const char *issuer = cupsJSONGetString(cupsJSONFind(metadata, "issuer"));
        const char *auth_endpoint = cupsJSONGetString(cupsJSONFind(metadata, "authorization_endpoint"));
        const char *token_endpoint = cupsJSONGetString(cupsJSONFind(metadata, "token_endpoint"));

        (void)issuer;
        (void)auth_endpoint;
        (void)token_endpoint;

        cupsJSONDelete(metadata);
    }

    // Test with custom metadata if we have fuzz data
    if (num_segments > 6 && seg_sizes[6] > 0)
    {
        char json_data[1024];
        size_t copy_len = seg_sizes[6] < sizeof(json_data) - 1 ? seg_sizes[6] : sizeof(json_data) - 1;
        memcpy(json_data, segments[6], copy_len);
        json_data[copy_len] = '\0';

        // Try to parse as JSON
        cups_json_t *custom_json = cupsJSONImportString(json_data);
        if (custom_json)
        {
            // Test JSON manipulation
            cupsJSONGetCount(custom_json);
            cupsJSONGetType(custom_json);

            cupsJSONDelete(custom_json);
        }
    }
}

// Test OAuth authorization flow simulation
static void test_oauth_authorization_flow(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (!g_temp_auth_uri || !g_temp_resource_uri)
        return;

    // Test cupsOAuthMakeBase64Random
    char *random_state = cupsOAuthMakeBase64Random(32);
    if (random_state)
    {
        free(random_state);
    }

    char *random_nonce = cupsOAuthMakeBase64Random(16);
    if (random_nonce)
    {
        free(random_nonce);
    }

    // Test authorization URL construction
    char *auth_url = cupsOAuthCopyAuthorizationURL(g_temp_auth_uri, g_temp_resource_uri, "http://localhost:8080", NULL);
    if (auth_url)
    {
        free(auth_url);
    }

    // Test with custom scopes and parameters if available
    if (num_segments > 7 && seg_sizes[7] > 0)
    {
        char scope_data[256];
        size_t copy_len = seg_sizes[7] < sizeof(scope_data) - 1 ? seg_sizes[7] : sizeof(scope_data) - 1;
        memcpy(scope_data, segments[7], copy_len);
        scope_data[copy_len] = '\0';

        // Clean scope data
        for (size_t i = 0; i < copy_len; i++)
        {
            if (!isalnum(scope_data[i]) && scope_data[i] != ':' && scope_data[i] != ' ')
            {
                scope_data[i] = 'r';
            }
        }

        // Try authorization with custom scope
        char *scoped_url = cupsOAuthCopyAuthorizationURL(g_temp_auth_uri, g_temp_resource_uri, "http://localhost:8080", scope_data);
        if (scoped_url)
        {
            free(scoped_url);
        }
    }
}

// Test OAuth error handling and edge cases
static void test_oauth_error_handling(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    // Test with NULL parameters
    cupsOAuthClearTokens(NULL, NULL);
    cupsOAuthClearTokens(g_temp_auth_uri, NULL);
    cupsOAuthClearTokens(NULL, g_temp_resource_uri);

    char *null_result = cupsOAuthCopyAccessToken(NULL, NULL, NULL);
    if (null_result)
    {
        free(null_result);
    }

    // Test with malformed URIs if we have data
    if (num_segments > 8 && seg_sizes[8] > 0)
    {
        char malformed_uri[256];
        size_t copy_len = seg_sizes[8] < sizeof(malformed_uri) - 1 ? seg_sizes[8] : sizeof(malformed_uri) - 1;
        memcpy(malformed_uri, segments[8], copy_len);
        malformed_uri[copy_len] = '\0';

        // Test with malformed URI
        cupsOAuthClearTokens(malformed_uri, g_temp_resource_uri);

        char *error_result = cupsOAuthCopyAccessToken(malformed_uri, g_temp_resource_uri, NULL);
        if (error_result)
        {
            free(error_result);
        }

        cups_json_t *error_metadata = cupsOAuthCopyMetadata(malformed_uri);
        if (error_metadata)
        {
            cupsJSONDelete(error_metadata);
        }
    }

    // Test with invalid token data
    cupsOAuthSaveTokens(g_temp_auth_uri, g_temp_resource_uri, "", 0, "", "");
    cupsOAuthSaveTokens(g_temp_auth_uri, g_temp_resource_uri, NULL, -1, NULL, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Minimum size check
    if (size < 40)
    {
        return 0;
    }

    // Setup cleanup
    atexit(cleanup_oauth_resources);

    // Parse input segments
    const uint8_t *segments[12];
    size_t seg_sizes[12];
    int num_segments = parse_oauth_segments(data, size, segments, seg_sizes, 12);

    if (num_segments < 1)
    {
        return 0;
    }

    // Create test OAuth URIs
    create_test_oauth_uris(segments, seg_sizes, num_segments);

    if (!g_temp_auth_uri || !g_temp_resource_uri)
    {
        return 0;
    }

    // Test various OAuth functionality
    test_oauth_token_operations(segments, seg_sizes, num_segments);
    test_oauth_client_data(segments, seg_sizes, num_segments);
    test_oauth_metadata_operations(segments, seg_sizes, num_segments);
    test_oauth_authorization_flow(segments, seg_sizes, num_segments);
    test_oauth_error_handling(segments, seg_sizes, num_segments);

    // Cleanup tokens for this iteration
    if (g_temp_auth_uri && g_temp_resource_uri)
    {
        cupsOAuthClearTokens(g_temp_auth_uri, g_temp_resource_uri);
    }

    return 0;
}
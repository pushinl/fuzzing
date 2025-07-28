/*
 * JSON Parser Fuzzer for libcups
 *
 * This fuzzer tests JSON parsing, manipulation, and export functionality
 * in the libcups library.
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
#include "json.h"

// Global variables for cleanup
static char *g_temp_file = NULL;

// Cleanup function
static void cleanup_files(void)
{
    if (g_temp_file)
    {
        unlink(g_temp_file);
        free(g_temp_file);
        g_temp_file = NULL;
    }
}

// Parse input data into segments
static int parse_json_segments(const uint8_t *data, size_t size,
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

// Create test JSON from input data
static char *create_test_json(const uint8_t *data, size_t size)
{
    if (size == 0)
        return NULL;

    char *json_str = malloc(size + 1);
    if (!json_str)
        return NULL;

    memcpy(json_str, data, size);
    json_str[size] = '\0';

    // Basic sanitization for printable characters
    for (size_t i = 0; i < size; i++)
    {
        if (json_str[i] == '\0')
        {
            json_str[i] = ' ';
        }
    }

    return json_str;
}

// Test JSON import and manipulation functions
static void test_json_operations(const char *json_str)
{
    if (!json_str)
        return;

    cups_json_t *json = NULL;
    char *exported_str = NULL;
    cups_json_t *found_node = NULL;

    // Test cupsJSONImportString
    json = cupsJSONImportString(json_str);
    if (json)
    {
        // Test cupsJSONGetCount
        size_t count = cupsJSONGetCount(json);
        (void)count; // Silence unused variable warning

        // Test cupsJSONGetType
        cups_jtype_t type = cupsJSONGetType(json);
        (void)type;

        // Test cupsJSONFind with various keys
        const char *test_keys[] = {"key", "name", "value", "data", "test"};
        for (int i = 0; i < 5; i++)
        {
            found_node = cupsJSONFind(json, test_keys[i]);
            if (found_node)
            {
                // Test cupsJSONGetString
                const char *str_val = cupsJSONGetString(found_node);
                (void)str_val;

                // Test cupsJSONGetNumber
                double num_val = cupsJSONGetNumber(found_node);
                (void)num_val;
            }
        }

        // Test cupsJSONGetChild
        cups_json_t *child = cupsJSONGetChild(json);
        if (child)
        {
            // Test cupsJSONGetSibling
            cups_json_t *sibling = cupsJSONGetSibling(child);
            (void)sibling;

            // Test cupsJSONGetKey
            const char *key = cupsJSONGetKey(child);
            (void)key;
        }

        // Test cupsJSONExportString
        exported_str = cupsJSONExportString(json);
        if (exported_str)
        {
            // Test re-importing exported JSON
            cups_json_t *reimported = cupsJSONImportString(exported_str);
            if (reimported)
            {
                cupsJSONDelete(reimported);
            }
            free(exported_str);
        }

        // Test cupsJSONExportFile
        g_temp_file = malloc(256);
        if (g_temp_file)
        {
            snprintf(g_temp_file, 256, "/tmp/fuzz_json_%d.json", getpid());
            if (cupsJSONExportFile(json, g_temp_file))
            {
                // Test cupsJSONImportFile
                cups_json_t *file_imported = cupsJSONImportFile(g_temp_file);
                if (file_imported)
                {
                    cupsJSONDelete(file_imported);
                }
            }
        }

        cupsJSONDelete(json);
    }
}

// Test JSON manipulation functions
static void test_json_manipulation(const uint8_t *data, size_t size)
{
    if (size < 16)
        return;

    cups_json_t *root = cupsJSONNew(NULL, NULL, CUPS_JTYPE_OBJECT);
    if (!root)
        return;

    // Create various nodes based on input data
    for (size_t i = 0; i < size && i < 100; i += 4)
    {
        if (i + 4 > size)
            break;

        uint8_t op = data[i] % 6;
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "key_%zu", i);

        cups_json_t *key_node = cupsJSONNewKey(root, NULL, key_buf);
        if (!key_node)
            continue;

        switch (op)
        {
        case 0: // String
        {
            char value_buf[64];
            snprintf(value_buf, sizeof(value_buf), "value_%d", data[i + 1]);
            cupsJSONNewString(root, key_node, value_buf);
        }
        break;
        case 1: // Number
        {
            double num = (double)(data[i + 1] | (data[i + 2] << 8));
            cupsJSONNewNumber(root, key_node, num);
        }
        break;
        case 2: // Boolean true
            cupsJSONNew(root, key_node, CUPS_JTYPE_TRUE);
            break;
        case 3: // Boolean false
            cupsJSONNew(root, key_node, CUPS_JTYPE_FALSE);
            break;
        case 4: // Null
            cupsJSONNew(root, key_node, CUPS_JTYPE_NULL);
            break;
        case 5: // Array
        {
            cups_json_t *array = cupsJSONNew(root, key_node, CUPS_JTYPE_ARRAY);
            if (array)
            {
                // Add some array elements
                cupsJSONNewString(array, NULL, "element1");
                cupsJSONNewNumber(array, NULL, 42.0);
            }
        }
        break;
        }
    }

    // Test operations on the constructed JSON
    char *exported = cupsJSONExportString(root);
    if (exported)
    {
        test_json_operations(exported);
        free(exported);
    }

    cupsJSONDelete(root);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
    {
        return 0;
    }

    // Setup cleanup handler
    atexit(cleanup_files);

    const uint8_t *segments[8];
    size_t seg_sizes[8];
    int num_segments = parse_json_segments(data, size, segments, seg_sizes, 8);

    // Test 1: Direct JSON string parsing
    for (int i = 0; i < num_segments; i++)
    {
        char *json_str = create_test_json(segments[i], seg_sizes[i]);
        if (json_str)
        {
            test_json_operations(json_str);
            free(json_str);
        }
    }

    // Test 2: JSON manipulation and construction
    test_json_manipulation(data, size);

    // Cleanup
    cleanup_files();

    return 0;
}
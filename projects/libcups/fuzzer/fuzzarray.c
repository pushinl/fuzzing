/*
 * Array Operations Fuzzer for libcups
 *
 * This fuzzer tests array creation, manipulation, searching, and sorting
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
#include "cups.h"

// Parse input data into string segments
static int parse_array_segments(const uint8_t *data, size_t size,
                                char **strings, int max_strings)
{
    if (size < 4)
        return 0;

    uint32_t num_strings = *(uint32_t *)data % max_strings + 1;
    data += 4;
    size -= 4;

    size_t pos = 0;
    int count = 0;

    for (uint32_t i = 0; i < num_strings && count < max_strings && pos < size; i++)
    {
        if (pos + 2 >= size)
            break;

        uint16_t str_len = *(uint16_t *)(data + pos) % (size - pos - 2) + 1;
        pos += 2;

        if (pos + str_len <= size)
        {
            strings[count] = malloc(str_len + 1);
            if (strings[count])
            {
                memcpy(strings[count], data + pos, str_len);
                strings[count][str_len] = '\0';

                // Basic sanitization for printable characters
                for (size_t j = 0; j < str_len; j++)
                {
                    if (strings[count][j] == '\0')
                    {
                        strings[count][j] = ' ';
                    }
                }

                count++;
                pos += str_len;
            }
        }
    }

    return count;
}

// Custom compare function for testing
static int custom_compare(const void *a, const void *b, void *data)
{
    const char *str_a = (const char *)a;
    const char *str_b = (const char *)b;
    (void)data; // Unused

    return strcmp(str_a, str_b);
}

// Custom copy function for testing
static void *custom_copy(const void *element, void *data)
{
    const char *str = (const char *)element;
    (void)data; // Unused

    return strdup(str);
}

// Custom free function for testing
static void custom_free(void *element, void *data)
{
    (void)data; // Unused
    free(element);
}

// Test basic array operations
static void test_array_basic_operations(char **strings, int count)
{
    if (count == 0)
        return;

    // Test cupsArrayNew with different parameters
    cups_array_t *array1 = cupsArrayNew((cups_array_cb_t)strcmp, NULL, NULL, 0, NULL, NULL);
    if (array1)
    {
        // Test cupsArrayAdd
        for (int i = 0; i < count; i++)
        {
            bool added = cupsArrayAdd(array1, strings[i]);
            (void)added;
        }

        // Test cupsArrayGetCount
        int array_count = cupsArrayGetCount(array1);
        (void)array_count;

        // Test cupsArrayGetFirst
        void *first = cupsArrayGetFirst(array1);
        (void)first;

        // Test cupsArrayGetLast
        void *last = cupsArrayGetLast(array1);
        (void)last;

        // Test cupsArrayGetNext and cupsArrayGetPrev
        if (first)
        {
            void *next = cupsArrayGetNext(array1);
            (void)next;

            if (next)
            {
                void *prev = cupsArrayGetPrev(array1);
                (void)prev;
            }
        }

        // Test cupsArrayFind
        for (int i = 0; i < count && i < 5; i++)
        {
            void *found = cupsArrayFind(array1, strings[i]);
            (void)found;
        }

        // Test cupsArrayGetCurrent
        void *current = cupsArrayGetCurrent(array1);
        (void)current;

        // Test cupsArrayGetIndex
        int index = cupsArrayGetIndex(array1);
        (void)index;

        // Test cupsArrayGetElement
        for (int i = 0; i < array_count && i < 10; i++)
        {
            void *element = cupsArrayGetElement(array1, i);
            (void)element;
        }

        cupsArrayDelete(array1);
    }
}

// Test array with custom functions
static void test_array_custom_functions(char **strings, int count)
{
    if (count == 0)
        return;

    // Test cupsArrayNew with custom copy and free functions
    cups_array_t *array = cupsArrayNew(
        custom_compare,
        (void *)"test_data",
        NULL,
        0,
        custom_copy,
        custom_free);

    if (array)
    {
        // Test cupsArrayGetUserData
        void *user_data = cupsArrayGetUserData(array);
        (void)user_data;

        // Add elements (they will be copied)
        for (int i = 0; i < count; i++)
        {
            cupsArrayAdd(array, strings[i]);
        }

        // Test cupsArrayDup
        cups_array_t *dup_array = cupsArrayDup(array);
        if (dup_array)
        {
            // Verify duplicate has same count
            int orig_count = cupsArrayGetCount(array);
            int dup_count = cupsArrayGetCount(dup_array);
            (void)orig_count;
            (void)dup_count;

            cupsArrayDelete(dup_array);
        }

        // Test cupsArrayRemove
        if (count > 0)
        {
            // Find first element and remove it
            void *first = cupsArrayGetFirst(array);
            if (first)
            {
                bool removed = cupsArrayRemove(array, first);
                (void)removed;
            }
        }

        cupsArrayDelete(array);
    }
}
// Test array with NULL and empty elements
static void test_array_null_empty(void)
{
    cups_array_t *array = cupsArrayNew((cups_array_cb_t)strcmp, NULL, NULL, 0, NULL, NULL);
    if (array)
    {
        // Test adding NULL (should be ignored or handled gracefully)
        bool added_null = cupsArrayAdd(array, NULL);
        (void)added_null;

        // Test adding empty string
        bool added_empty = cupsArrayAdd(array, "");
        (void)added_empty;

        // Test finding NULL
        void *found_null = cupsArrayFind(array, NULL);
        (void)found_null;

        // Test operations on potentially empty array
        int count = cupsArrayGetCount(array);
        void *first = cupsArrayGetFirst(array);
        void *last = cupsArrayGetLast(array);
        (void)count;
        (void)first;
        (void)last;

        cupsArrayDelete(array);
    }
}

// Test array stress operations
static void test_array_stress(const uint8_t *data, size_t size)
{
    if (size < 32)
        return;

    cups_array_t *array = cupsArrayNew(
        (cups_array_cb_t)strcmp,
        NULL,
        NULL,
        0,
        (cups_acopy_cb_t)strdup,
        (cups_afree_cb_t)free);

    if (array)
    {
        // Add many elements
        for (size_t i = 0; i < size && i < 1000; i += 4)
        {
            char stress_str[64];
            snprintf(stress_str, sizeof(stress_str), "stress_%zu_%d_%d_%d_%d",
                     i, data[i], data[i + 1], data[i + 2], data[i + 3]);
            cupsArrayAdd(array, stress_str);
        }

        // Test intensive searching
        for (size_t i = 0; i < size && i < 100; i += 8)
        {
            char search_str[64];
            snprintf(search_str, sizeof(search_str), "stress_%zu_%d_%d_%d_%d",
                     i, data[i], data[i + 1], data[i + 2], data[i + 3]);
            void *found = cupsArrayFind(array, search_str);
            (void)found;
        }

        // Test iteration through large array
        void *element = cupsArrayGetFirst(array);
        int iteration_count = 0;
        while (element && iteration_count < 500)
        {
            element = cupsArrayGetNext(array);
            iteration_count++;
        }

        cupsArrayDelete(array);
    }
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
    {
        return 0;
    }

    // Parse input into string segments
    char *strings[64];
    int string_count = parse_array_segments(data, size, strings, 64);

    // Test 1: Basic array operations
    test_array_basic_operations(strings, string_count);

    // Test 2: Array with custom functions
    test_array_custom_functions(strings, string_count);

    // Test 3: NULL and empty element handling
    test_array_null_empty();

    // Test 4: Stress testing with many elements
    if (size >= 32)
    {
        test_array_stress(data, size);
    }

    // Cleanup allocated strings
    for (int i = 0; i < string_count; i++)
    {
        free(strings[i]);
    }

    return 0;
}
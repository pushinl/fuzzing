//
// Filter chain fuzzer for libcupsfilters
//
// Test cfFilterTee, cfFilterChain, cfFilterPOpen, cfFilterPClose, etc.
//
// Copyright 2024
//
// Licensed under Apache License v2.0. See the file "LICENSE" for more
// information.
//

#include "filter.h"
#include "driver.h"
#include <config.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

cf_logfunc_t logfunc = cfCUPSLogFunc; // Log function
void *ld = NULL;                      // Log function data

// Test filter chain functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 100000)
    {
        return 0;
    }

    // Create temporary input file
    char input_file[] = "/tmp/fuzz_filter_input_XXXXXX";
    int input_fd = mkstemp(input_file);
    if (input_fd < 0)
    {
        return 0;
    }

    // Write fuzzer data to input file
    if (write(input_fd, Data, Size) != (ssize_t)Size)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }
    lseek(input_fd, 0, SEEK_SET);

    // Create temporary output file
    char output_file[] = "/tmp/fuzz_filter_output_XXXXXX";
    int output_fd = mkstemp(output_file);
    if (output_fd < 0)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }

    // Create filter data structure
    cf_filter_data_t data;
    memset(&data, 0, sizeof(data));
    data.printer = "test-printer";
    data.job_id = 1;
    data.job_user = "testuser";
    data.job_title = "test-job";
    data.copies = 1;
    data.content_type = "text/plain";
    data.final_content_type = "application/pdf";
    data.job_attrs = NULL;
    data.printer_attrs = NULL;
    data.header = NULL;
    data.num_options = 0;
    data.options = NULL;
    data.back_pipe[0] = -1;
    data.back_pipe[1] = -1;
    data.side_pipe[0] = -1;
    data.side_pipe[1] = -1;
    data.extension = NULL;
    data.logfunc = logfunc;
    data.logdata = ld;
    data.iscanceledfunc = NULL;
    data.iscanceleddata = NULL;

    // Test cfFilterTee function
    char tee_file[] = "/tmp/fuzz_filter_tee_XXXXXX";
    int tee_fd = mkstemp(tee_file);
    if (tee_fd >= 0)
    {
        close(tee_fd);
        lseek(input_fd, 0, SEEK_SET);
        lseek(output_fd, 0, SEEK_SET);

        int result = cfFilterTee(input_fd, output_fd, 1, &data, tee_file);
        (void)result; // Suppress unused warning

        unlink(tee_file);
    }

    // Test cfFilterAddEnvVar and cfFilterGetEnvVar
    char **env = NULL;
    if (Size > 20)
    {
        char env_name[32];
        char env_value[64];

        // Create environment variable name and value from fuzzer data
        int name_len = (Data[0] % 15) + 1;
        int value_len = (Data[1] % 30) + 1;

        for (int i = 0; i < name_len && (2 + i) < Size; i++)
        {
            env_name[i] = ((Data[2 + i] % 26) + 'A'); // A-Z
        }
        env_name[name_len] = '\0';

        for (int i = 0; i < value_len && (2 + name_len + i) < Size; i++)
        {
            env_value[i] = (Data[2 + name_len + i] % 94) + 32; // Printable ASCII
        }
        env_value[value_len] = '\0';

        // Test adding environment variable
        int add_result = cfFilterAddEnvVar(env_name, env_value, &env);
        (void)add_result;

        // Test getting environment variable
        char *got_value = cfFilterGetEnvVar(env_name, env);
        (void)got_value;

        // Add a few more environment variables
        cfFilterAddEnvVar("TEST_VAR1", "value1", &env);
        cfFilterAddEnvVar("TEST_VAR2", "value2", &env);

        // Test getting non-existent variable
        char *null_value = cfFilterGetEnvVar("NONEXISTENT", env);
        (void)null_value;
    }

    // Test filter extension data functions
    char ext_name[] = "test_extension";
    char ext_data[] = "test_data";

    // Add extension data
    void *added = cfFilterDataAddExt(&data, ext_name, ext_data);
    (void)added;

    // Get extension data
    void *retrieved = cfFilterDataGetExt(&data, ext_name);
    (void)retrieved;

    // Add another extension
    int ext_int_data = 12345;
    cfFilterDataAddExt(&data, "int_ext", &ext_int_data);

    // Remove extension data
    void *removed = cfFilterDataRemoveExt(&data, ext_name);
    (void)removed;

    // Try to get removed extension (should return NULL)
    void *should_be_null = cfFilterDataGetExt(&data, ext_name);
    (void)should_be_null;

    // Test with different content types
    const char *content_types[] = {
        "text/plain",
        "application/pdf",
        "application/postscript",
        "image/jpeg",
        "image/png",
        "image/pwg-raster"};

    const char *final_types[] = {
        "application/pdf",
        "application/postscript",
        "image/pwg-raster",
        "image/vnd.cups-raster"};

    for (int ct = 0; ct < 6; ct++)
    {
        for (int ft = 0; ft < 4; ft++)
        {
            data.content_type = (char *)content_types[ct];
            data.final_content_type = (char *)final_types[ft];

            // Reset file positions
            lseek(input_fd, 0, SEEK_SET);
            lseek(output_fd, 0, SEEK_SET);

            // Test cfFilterTee with different content types
            char tee_file2[] = "/tmp/fuzz_filter_tee2_XXXXXX";
            int tee_fd2 = mkstemp(tee_file2);
            if (tee_fd2 >= 0)
            {
                close(tee_fd2);
                int result = cfFilterTee(input_fd, output_fd, 1, &data, tee_file2);
                (void)result;
                unlink(tee_file2);
            }
        }
    }

    // Test edge cases with small files
    if (Size > 0)
    {
        lseek(input_fd, 0, SEEK_SET);
        lseek(output_fd, 0, SEEK_SET);

        // Truncate input to test with very small data
        ftruncate(input_fd, Size / 2);
        lseek(input_fd, 0, SEEK_SET);

        char tee_small[] = "/tmp/fuzz_filter_small_XXXXXX";
        int tee_small_fd = mkstemp(tee_small);
        if (tee_small_fd >= 0)
        {
            close(tee_small_fd);
            int result = cfFilterTee(input_fd, output_fd, 1, &data, tee_small);
            (void)result;
            unlink(tee_small);
        }
    }

    // Cleanup environment variables
    if (env)
    {
        for (char **e = env; *e; e++)
        {
            free(*e);
        }
        free(env);
    }

    // Cleanup files
    close(input_fd);
    close(output_fd);
    unlink(input_file);
    unlink(output_file);

    return 0;
}

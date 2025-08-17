//
// Color separation fuzzer for libcupsfilters
//
// Test cfRGBNew, cfRGBDoGray, cfRGBDoRGB, cfCMYKNew, cfCMYKDoBlack, etc.
//
// Copyright 2024
//
// Licensed under Apache License v2.0. See the file "LICENSE" for more
// information.
//

#include "driver.h"
#include "filter.h"
#include <config.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

cf_logfunc_t logfunc = cfCUPSLogFunc; // Log function
void *ld = NULL;                      // Log function data

// Test RGB and CMYK color separation functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 20 || Size > 100000)
    {
        return 0;
    }

    // Redirect output to temporary file
    freopen("/tmp/fuzz_color_test", "w", stdout);
    freopen("/tmp/fuzz_color_test", "w", stderr);

    // Extract parameters from fuzzer data
    int num_samples = (Data[0] % 50) + 1; // 1-50 samples
    int cube_size = (Data[1] % 16) + 2;   // 2-17 cube size
    int num_channels = (Data[2] % 8) + 1; // 1-8 channels
    int num_pixels = (Data[3] % 100) + 1; // 1-100 pixels

    // Ensure we have enough data
    if (Size < (size_t)(20 + num_samples * 3 + num_pixels * num_channels))
    {
        fclose(stdout);
        fclose(stderr);
        return 0;
    }

    // Create sample data for RGB
    cf_sample_t *samples = (cf_sample_t *)malloc(num_samples * sizeof(cf_sample_t));
    if (!samples)
    {
        fclose(stdout);
        fclose(stderr);
        return 0;
    }

    // Initialize samples from fuzzer data
    for (int i = 0; i < num_samples; i++)
    {
        int offset = 4 + i * 3;
        samples[i].rgb[0] = Data[offset % Size];
        samples[i].rgb[1] = Data[(offset + 1) % Size];
        samples[i].rgb[2] = Data[(offset + 2) % Size];
    }

    // Test RGB color separation
    cf_rgb_t *rgb = cfRGBNew(num_samples, samples, cube_size, num_channels);
    if (rgb)
    {
        // Create input and output buffers
        unsigned char *input = (unsigned char *)malloc(num_pixels * 3);
        unsigned char *output = (unsigned char *)malloc(num_pixels * num_channels);

        if (input && output)
        {
            // Fill input with fuzzer data
            for (int i = 0; i < num_pixels * 3; i++)
            {
                input[i] = Data[(10 + i) % Size];
            }

            // Test RGB separation functions
            cfRGBDoGray(rgb, input, output, num_pixels);
            cfRGBDoRGB(rgb, input, output, num_pixels);
        }

        free(input);
        free(output);
        cfRGBDelete(rgb);
    }

    // Test CMYK color separation
    cf_cmyk_t *cmyk = cfCMYKNew(num_channels);
    if (cmyk)
    {
        // Test CMYK configuration functions
        float black_lower = (float)(Data[4] % 100) / 100.0f;
        float black_upper = (float)(Data[5] % 100) / 100.0f + black_lower;
        if (black_upper > 1.0f)
            black_upper = 1.0f;

        cfCMYKSetBlack(cmyk, black_lower, black_upper, logfunc, ld);

        // Test gamma setting for different channels
        for (int ch = 0; ch < num_channels && ch < 4; ch++)
        {
            float gamma = (float)(Data[6 + ch] % 50 + 50) / 100.0f; // 0.5 to 1.0
            cfCMYKSetGamma(cmyk, ch, gamma, logfunc, ld);
        }

        // Test curve setting with sample points
        if (Size > 30)
        {
            float xypoints[8]; // 4 points, x,y pairs
            for (int i = 0; i < 8; i++)
            {
                xypoints[i] = (float)(Data[10 + i] % 100) / 100.0f;
            }
            cfCMYKSetCurve(cmyk, 0, 4, xypoints, logfunc, ld);
        }

        // Test ink limit
        float ink_limit = (float)(Data[8] % 300 + 100) / 100.0f; // 1.0 to 4.0
        cfCMYKSetInkLimit(cmyk, ink_limit, logfunc, ld);

        // Create input and output buffers for CMYK operations
        unsigned char *input = (unsigned char *)malloc(num_pixels * 3);
        short *output = (short *)malloc(num_pixels * num_channels * sizeof(short));

        if (input && output)
        {
            // Fill input with fuzzer data
            for (int i = 0; i < num_pixels * 3; i++)
            {
                input[i] = Data[(20 + i) % Size];
            }

            // Test CMYK separation functions
            cfCMYKDoBlack(cmyk, input, output, num_pixels);
            cfCMYKDoCMYK(cmyk, input, output, num_pixels);
            cfCMYKDoGray(cmyk, input, output, num_pixels);
            cfCMYKDoRGB(cmyk, input, output, num_pixels);
        }

        free(input);
        free(output);
        cfCMYKDelete(cmyk);
    }

    // Test packing functions
    if (Size > 50)
    {
        int pack_width = (Data[9] % 100) + 1;
        unsigned char *pack_input = (unsigned char *)malloc(pack_width);
        unsigned char *pack_output = (unsigned char *)malloc(pack_width);

        if (pack_input && pack_output)
        {
            // Fill with fuzzer data
            for (int i = 0; i < pack_width; i++)
            {
                pack_input[i] = Data[(30 + i) % Size];
            }

            // Test horizontal packing
            unsigned char on_mask = Data[10] % 256;
            int num_comps = (Data[11] % 4) + 1;
            cfPackHorizontal(pack_input, pack_output, pack_width, on_mask, num_comps);

            // Test horizontal packing 2
            cfPackHorizontal2(pack_input, pack_output, pack_width, num_comps);

            // Test horizontal bit packing
            unsigned char off_mask = Data[12] % 256;
            cfPackHorizontalBit(pack_input, pack_output, pack_width, on_mask, off_mask);

            // Test vertical packing
            cfPackVertical(pack_input, pack_output, pack_width, on_mask, num_comps);
        }

        free(pack_input);
        free(pack_output);
    }

    // Cleanup
    free(samples);
    fclose(stdout);
    fclose(stderr);

    return 0;
}

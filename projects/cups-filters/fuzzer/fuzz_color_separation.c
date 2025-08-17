//
// Color separation fuzzer for cups-filters
//
// Test cupsRGBNew, cupsRGBDoGray, cupsRGBDoRGB, cupsCMYKNew, cupsCMYKDoBlack, etc.
//
// Copyright 2024
//
// Based on fuzz_pdf.c reference implementation
//

#include "../cupsfilters/driver.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

static void redirect_stdout_stderr(); // hide stdout

// Test RGB and CMYK color separation functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 20 || Size > 50000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Extract parameters from fuzzer data
    int num_samples = (Data[0] % 20) + 1; // 1-20 samples
    int cube_size = (Data[1] % 8) + 2;    // 2-9 cube size
    int num_channels = (Data[2] % 4) + 1; // 1-4 channels
    int num_pixels = (Data[3] % 50) + 1;  // 1-50 pixels

    // Ensure we have enough data
    if (Size < (size_t)(20 + num_samples * 3 + num_pixels * 3))
    {
        return 0;
    }

    // Create sample data for RGB
    cups_sample_t *samples = (cups_sample_t *)malloc(num_samples * sizeof(cups_sample_t));
    if (!samples)
    {
        return 0;
    }

    // Initialize samples from fuzzer data
    for (int i = 0; i < num_samples; i++)
    {
        int offset = 4 + i * 3;
        if (offset + 2 < Size)
        {
            samples[i].rgb[0] = Data[offset];
            samples[i].rgb[1] = Data[offset + 1];
            samples[i].rgb[2] = Data[offset + 2];
            // Initialize colors array
            for (int j = 0; j < CUPS_MAX_RGB && j < num_channels; j++)
            {
                samples[i].colors[j] = Data[(offset + j) % Size];
            }
        }
    }

    // Test RGB color separation
    cups_rgb_t *rgb = cupsRGBNew(num_samples, samples, cube_size, num_channels);
    if (rgb)
    {
        // Create input and output buffers
        unsigned char *input = (unsigned char *)malloc(num_pixels * 3);
        unsigned char *output = (unsigned char *)malloc(num_pixels * num_channels);

        if (input && output)
        {
            // Fill input with fuzzer data
            for (int i = 0; i < num_pixels * 3 && (10 + i) < Size; i++)
            {
                input[i] = Data[10 + i];
            }

            // Test RGB separation functions
            cupsRGBDoGray(rgb, input, output, num_pixels);
            cupsRGBDoRGB(rgb, input, output, num_pixels);
        }

        if (input)
            free(input);
        if (output)
            free(output);
        cupsRGBDelete(rgb);
    }

    // Test CMYK color separation
    cups_cmyk_t *cmyk = cupsCMYKNew(num_channels);
    if (cmyk)
    {
        // Test CMYK configuration functions
        float black_lower = (float)(Data[4] % 50) / 100.0f;
        float black_upper = (float)(Data[5] % 50 + 50) / 100.0f;

        cupsCMYKSetBlack(cmyk, black_lower, black_upper);

        // Test gamma setting for different channels
        for (int ch = 0; ch < num_channels && ch < 4; ch++)
        {
            float gamma = (float)(Data[6 + ch] % 50 + 50) / 100.0f; // 0.5 to 1.0
            float density = (float)(Data[10 + ch] % 100) / 100.0f;  // 0.0 to 1.0
            cupsCMYKSetGamma(cmyk, ch, gamma, density);
        }

        // Test curve setting with sample points
        if (Size > 30)
        {
            float xypoints[8]; // 4 points, x,y pairs
            for (int i = 0; i < 8 && (15 + i) < Size; i++)
            {
                xypoints[i] = (float)(Data[15 + i] % 100) / 100.0f;
            }
            cupsCMYKSetCurve(cmyk, 0, 4, xypoints);
        }

        // Test ink limit
        float ink_limit = (float)(Data[8] % 200 + 100) / 100.0f; // 1.0 to 3.0
        cupsCMYKSetInkLimit(cmyk, ink_limit);

        // Create input and output buffers for CMYK operations
        unsigned char *input = (unsigned char *)malloc(num_pixels * 3);
        short *output = (short *)malloc(num_pixels * num_channels * sizeof(short));

        if (input && output)
        {
            // Fill input with fuzzer data
            for (int i = 0; i < num_pixels * 3 && (25 + i) < Size; i++)
            {
                input[i] = Data[25 + i];
            }

            // Test CMYK separation functions
            cupsCMYKDoBlack(cmyk, input, output, num_pixels);
            cupsCMYKDoCMYK(cmyk, input, output, num_pixels);
            cupsCMYKDoGray(cmyk, input, output, num_pixels);
            cupsCMYKDoRGB(cmyk, input, output, num_pixels);
        }

        if (input)
            free(input);
        if (output)
            free(output);
        cupsCMYKDelete(cmyk);
    }

    // Test packing functions
    if (Size > 40)
    {
        int pack_width = (Data[9] % 50) + 1;
        unsigned char *pack_input = (unsigned char *)malloc(pack_width);
        unsigned char *pack_output = (unsigned char *)malloc(pack_width);

        if (pack_input && pack_output)
        {
            // Fill with fuzzer data
            for (int i = 0; i < pack_width && (35 + i) < Size; i++)
            {
                pack_input[i] = Data[35 + i];
            }

            // Test horizontal packing
            unsigned char on_mask = Data[10] % 256;
            int num_comps = (Data[11] % 3) + 1;
            cupsPackHorizontal(pack_input, pack_output, pack_width, on_mask, num_comps);

            // Test horizontal packing 2
            cupsPackHorizontal2(pack_input, pack_output, pack_width, num_comps);

            // Test horizontal bit packing
            unsigned char off_mask = Data[12] % 256;
            cupsPackHorizontalBit(pack_input, pack_output, pack_width, on_mask, off_mask);

            // Test vertical packing
            cupsPackVertical(pack_input, pack_output, pack_width, on_mask, num_comps);
        }

        if (pack_input)
            free(pack_input);
        if (pack_output)
            free(pack_output);
    }

    // Cleanup
    free(samples);

    return 0;
}

void redirect_stdout_stderr()
{
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null < 0)
    {
        return;
    }
    dup2(dev_null, STDOUT_FILENO);
    dup2(dev_null, STDERR_FILENO);
    close(dev_null);
}

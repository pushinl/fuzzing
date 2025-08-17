#include <cupsfilters/driver.h>
#include <cupsfilters/raster.h>
#include <cups/cups.h>
#include <cups/ppd.h>
#include <cups/raster.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static void redirect_stdout_stderr(); // hide stdout

// Test raster and color separation functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 20 || Size > 100000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Extract parameters from fuzzer data
    int num_samples = (Data[0] % 50) + 1; // 1-50 samples
    int cube_size = (Data[1] % 16) + 2;   // 2-17 cube size
    int num_channels = (Data[2] % 8) + 1; // 1-8 channels
    int num_pixels = (Data[3] % 100) + 1; // 1-100 pixels

    // Ensure we have enough data
    if (Size < (size_t)(20 + num_samples * 3 + num_pixels * num_channels))
    {
        return 0;
    }

    // Test RGB color separation
    cups_sample_t *samples = (cups_sample_t *)malloc(num_samples * sizeof(cups_sample_t));
    if (!samples)
    {
        return 0;
    }

    // Initialize samples from fuzzer data
    for (int i = 0; i < num_samples; i++)
    {
        int offset = 4 + i * 3;
        samples[i].rgb[0] = Data[offset % Size];
        samples[i].rgb[1] = Data[(offset + 1) % Size];
        samples[i].rgb[2] = Data[(offset + 2) % Size];

        // Fill color values
        for (int j = 0; j < CUPS_MAX_RGB && j < num_channels; j++)
        {
            samples[i].colors[j] = Data[(offset + j + 3) % Size];
        }
    }

    // Test cupsRGBNew
    cups_rgb_t *rgb = cupsRGBNew(num_samples, samples, cube_size, num_channels);
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
            cupsRGBDoGray(rgb, input, output, num_pixels);
            cupsRGBDoRGB(rgb, input, output, num_pixels);
        }

        free(input);
        free(output);
        cupsRGBDelete(rgb);
    }

    // Test CMYK color separation
    cups_cmyk_t *cmyk = cupsCMYKNew(num_channels);
    if (cmyk)
    {
        // Test CMYK configuration functions (if available)
        // Note: Some CMYK configuration functions might not be available in this branch

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
            cupsCMYKDoBlack(cmyk, input, output, num_pixels);
            cupsCMYKDoCMYK(cmyk, input, output, num_pixels);
            cupsCMYKDoGray(cmyk, input, output, num_pixels);
            cupsCMYKDoRGB(cmyk, input, output, num_pixels);
        }

        free(input);
        free(output);
        cupsCMYKDelete(cmyk);
    }

    // Test byte checking functions
    if (Size > 50)
    {
        int check_width = (Data[4] % 100) + 1;
        unsigned char *check_data = (unsigned char *)malloc(check_width);

        if (check_data)
        {
            // Fill with fuzzer data
            for (int i = 0; i < check_width; i++)
            {
                check_data[i] = Data[(50 + i) % Size];
            }

            // Test byte checking functions
            int check_result = cupsCheckBytes(check_data, check_width);
            (void)check_result;

            unsigned char check_value = Data[5] % 256;
            check_result = cupsCheckValue(check_data, check_width, check_value);
            (void)check_result;
        }

        free(check_data);
    }

    // Test LUT functions with sample data
    if (Size > 60)
    {
        int lut_values = (Data[6] % 10) + 2;
        float *lut_vals = (float *)malloc(lut_values * sizeof(float));

        if (lut_vals)
        {
            // Create LUT values from fuzzer data
            for (int i = 0; i < lut_values; i++)
            {
                int offset = 60 + i * 4;
                unsigned int val = (Data[offset % Size] << 8) | Data[(offset + 1) % Size];
                lut_vals[i] = (float)(val % 1000) / 1000.0f;
            }

            // Sort values
            for (int i = 0; i < lut_values - 1; i++)
            {
                for (int j = i + 1; j < lut_values; j++)
                {
                    if (lut_vals[i] > lut_vals[j])
                    {
                        float temp = lut_vals[i];
                        lut_vals[i] = lut_vals[j];
                        lut_vals[j] = temp;
                    }
                }
            }

            cups_lut_t *lut = cupsLutNew(lut_values, lut_vals);
            if (lut)
            {
                cupsLutDelete(lut);
            }
        }

        free(lut_vals);
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
#include <cupsfilters/driver.h>
#include <cups/cups.h>
#include <cups/ppd.h>
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

// Test dithering and LUT functions (closest to text processing in current branch)
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 5 || Size > 100000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Extract parameters from fuzzer data
    int num_values = (Data[0] % 16) + 2; // 2-17 values
    int width = (Data[1] % 512) + 1;     // 1-512 width

    // Ensure we have enough data
    if (Size < (size_t)(num_values * 4 + 10))
    {
        return 0;
    }

    // Create LUT values from fuzzer data
    float *values = (float *)malloc(num_values * sizeof(float));
    if (!values)
    {
        return 0;
    }

    // Initialize values from fuzzer data
    for (int i = 0; i < num_values; i++)
    {
        int offset = 2 + i * 4;
        // Convert bytes to float value between 0.0 and 1.0
        unsigned int val = (Data[offset] << 24) | (Data[offset + 1] << 16) |
                           (Data[offset + 2] << 8) | Data[offset + 3];
        values[i] = (float)(val % 1000) / 1000.0f;
    }

    // Sort values to ensure proper LUT
    for (int i = 0; i < num_values - 1; i++)
    {
        for (int j = i + 1; j < num_values; j++)
        {
            if (values[i] > values[j])
            {
                float temp = values[i];
                values[i] = values[j];
                values[j] = temp;
            }
        }
    }

    // Test cupsLutNew
    cups_lut_t *lut = cupsLutNew(num_values, values);
    if (lut)
    {
        // Test cupsDitherNew
        cups_dither_t *dither = cupsDitherNew(width);
        if (dither)
        {
            // Create test data for dithering
            short *line = (short *)malloc(width * sizeof(short));
            unsigned char *pixels = (unsigned char *)malloc(width);

            if (line && pixels)
            {
                // Fill line with test data from fuzzer
                for (int i = 0; i < width; i++)
                {
                    int data_idx = (10 + i) % Size;
                    line[i] = (short)((Data[data_idx] * 16) % 4096); // Scale to 0-4095
                }

                // Test dithering
                cupsDitherLine(dither, lut, line, 1, pixels);

                // Test with multiple channels if we have enough data
                if (width > 4)
                {
                    short *multi_line = (short *)malloc(width * 3 * sizeof(short));
                    unsigned char *multi_pixels = (unsigned char *)malloc(width * 3);

                    if (multi_line && multi_pixels)
                    {
                        // Fill with RGB data
                        for (int i = 0; i < width * 3; i++)
                        {
                            int data_idx = (20 + i) % Size;
                            multi_line[i] = (short)((Data[data_idx] * 16) % 4096);
                        }

                        cupsDitherLine(dither, lut, multi_line, 3, multi_pixels);
                    }

                    free(multi_line);
                    free(multi_pixels);
                }
            }

            free(line);
            free(pixels);
            cupsDitherDelete(dither);
        }

        cupsLutDelete(lut);
    }

    // Test packing functions
    if (Size > 30)
    {
        int pack_width = (Data[2] % 100) + 1;
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
            unsigned char on_mask = Data[3] % 256;
            int num_comps = (Data[4] % 4) + 1;
            cupsPackHorizontal(pack_input, pack_output, pack_width, on_mask, num_comps);

            // Test horizontal packing 2
            cupsPackHorizontal2(pack_input, pack_output, pack_width, num_comps);

            // Test horizontal bit packing
            unsigned char off_mask = Data[5] % 256;
            cupsPackHorizontalBit(pack_input, pack_output, pack_width, on_mask, off_mask);

            // Test vertical packing
            cupsPackVertical(pack_input, pack_output, pack_width, on_mask, num_comps);
        }

        free(pack_input);
        free(pack_output);
    }

    // Cleanup
    free(values);

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
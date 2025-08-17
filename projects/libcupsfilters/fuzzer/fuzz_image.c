//
// Image processing fuzzer for libcupsfilters
//
// Test cfImageOpen, cfImageGetRow, cfImageGetCol, and color conversion functions
//
// Copyright 2024
//
// Licensed under Apache License v2.0. See the file "LICENSE" for more
// information.
//

#include "image.h"
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

// Test image processing functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 1000000)
    {
        return 0;
    }

    // Redirect output to temporary file
    freopen("/tmp/fuzz_image_test", "w", stdout);
    freopen("/tmp/fuzz_image_test", "w", stderr);

    // Create temporary file with fuzzer data
    char temp_file[] = "/tmp/fuzz_image_XXXXXX";
    int fd = mkstemp(temp_file);
    if (fd < 0)
    {
        return 0;
    }

    write(fd, Data, Size);
    close(fd);

    // Test cfImageOpen with different parameters
    cf_image_t *img = cfImageOpen(temp_file, CF_IMAGE_RGB, CF_IMAGE_WHITE, 100, 0, NULL);
    if (img)
    {
        // Test image properties
        unsigned width = cfImageGetWidth(img);
        unsigned height = cfImageGetHeight(img);
        unsigned xppi = cfImageGetXPPI(img);
        unsigned yppi = cfImageGetYPPI(img);
        int depth = cfImageGetDepth(img);
        cf_icspace_t colorspace = cfImageGetColorSpace(img);

        (void)width;
        (void)height;
        (void)xppi;
        (void)yppi;
        (void)depth;
        (void)colorspace;

        // Test image data access (with bounds checking)
        if (width > 0 && height > 0 && width < 10000 && height < 10000)
        {
            cf_ib_t *pixels = (cf_ib_t *)malloc(width * 3); // RGB
            if (pixels)
            {
                // Test getting rows and columns
                cfImageGetRow(img, 0, 0, width, pixels);
                if (height > 1)
                {
                    cfImageGetCol(img, 0, 0, height, pixels);
                }

                // Test color space conversion functions with sample data
                if (width >= 4)
                {
                    cf_ib_t *out_pixels = (cf_ib_t *)malloc(width * 4);
                    if (out_pixels)
                    {
                        // Test RGB conversions
                        cfImageRGBToBlack(pixels, out_pixels, width / 3);
                        cfImageRGBToCMY(pixels, out_pixels, width / 3);
                        cfImageRGBToCMYK(pixels, out_pixels, width / 3);
                        cfImageRGBToWhite(pixels, out_pixels, width / 3);

                        // Test CMYK conversions (if we have CMYK data)
                        cfImageCMYKToBlack(pixels, out_pixels, width / 4);
                        cfImageCMYKToCMY(pixels, out_pixels, width / 4);
                        cfImageCMYKToRGB(pixels, out_pixels, width / 4);
                        cfImageCMYKToWhite(pixels, out_pixels, width / 4);

                        // Test White conversions
                        cfImageWhiteToBlack(pixels, out_pixels, width);
                        cfImageWhiteToCMY(pixels, out_pixels, width);
                        cfImageWhiteToCMYK(pixels, out_pixels, width);
                        cfImageWhiteToRGB(pixels, out_pixels, width);

                        free(out_pixels);
                    }
                }
                free(pixels);
            }
        }

        // Test cropping if image is large enough
        if (width > 10 && height > 10)
        {
            cf_image_t *cropped = cfImageCrop(img, 2, 2, width / 2, height / 2);
            if (cropped)
            {
                cfImageClose(cropped);
            }
        }

        cfImageClose(img);
    }

    // Test cfImageOpenFP with FILE pointer
    FILE *fp = fopen(temp_file, "rb");
    if (fp)
    {
        img = cfImageOpenFP(fp, CF_IMAGE_WHITE, CF_IMAGE_RGB, 90, 10, NULL);
        if (img)
        {
            // Test image adjustment functions
            unsigned width = cfImageGetWidth(img);
            if (width > 0 && width < 1000)
            {
                cf_ib_t *pixels = (cf_ib_t *)malloc(width * 3);
                if (pixels)
                {
                    cfImageGetRow(img, 0, 0, width, pixels);
                    cfImageRGBAdjust(pixels, width, 50, 25); // Test RGB adjustment

                    // Test LUT application
                    cf_ib_t lut[256];
                    for (int i = 0; i < 256; i++)
                    {
                        lut[i] = 255 - i; // Invert LUT
                    }
                    cfImageLut(pixels, width * 3, lut);

                    free(pixels);
                }
            }
            cfImageClose(img);
        }
        fclose(fp);
    }

    // Test with different colorspace combinations
    img = cfImageOpen(temp_file, CF_IMAGE_CMYK, CF_IMAGE_RGB, 75, 45, NULL);
    if (img)
    {
        cfImageClose(img);
    }

    // Cleanup
    unlink(temp_file);
    fclose(stdout);
    fclose(stderr);

    return 0;
}

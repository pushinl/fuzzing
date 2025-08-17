#include <cupsfilters/image.h>
#include <cupsfilters/driver.h>
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

// Test image processing functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 500000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary input file
    char input_file[] = "/tmp/fuzz_image_input_XXXXXX";
    int input_fd = mkstemp(input_file);
    if (input_fd < 0)
    {
        return 0;
    }

    // Write fuzz data to input file
    if (write(input_fd, Data, Size) != (ssize_t)Size)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }
    close(input_fd);

    // Test cupsImageOpen with different colorspace combinations
    cups_image_t *img = cupsImageOpen(input_file, CUPS_IMAGE_RGB, CUPS_IMAGE_WHITE, 100, 0, NULL);
    if (img)
    {
        // Test image properties
        unsigned width = cupsImageGetWidth(img);
        unsigned height = cupsImageGetHeight(img);
        unsigned xppi = cupsImageGetXPPI(img);
        unsigned yppi = cupsImageGetYPPI(img);
        int depth = cupsImageGetDepth(img);
        cups_icspace_t colorspace = cupsImageGetColorSpace(img);

        (void)width;
        (void)height;
        (void)xppi;
        (void)yppi;
        (void)depth;
        (void)colorspace;

        // Test image data access (with bounds checking)
        if (width > 0 && height > 0 && width < 10000 && height < 10000)
        {
            cups_ib_t *pixels = (cups_ib_t *)malloc(width * 3); // RGB
            if (pixels)
            {
                // Test getting rows and columns
                cupsImageGetRow(img, 0, 0, width, pixels);
                if (height > 1)
                {
                    cupsImageGetCol(img, 0, 0, height, pixels);
                }

                // Test color space conversion functions with sample data
                if (width >= 4)
                {
                    cups_ib_t *out_pixels = (cups_ib_t *)malloc(width * 4);
                    if (out_pixels)
                    {
                        // Test RGB conversions
                        cupsImageRGBToBlack(pixels, out_pixels, width / 3);
                        cupsImageRGBToCMY(pixels, out_pixels, width / 3);
                        cupsImageRGBToCMYK(pixels, out_pixels, width / 3);
                        cupsImageRGBToWhite(pixels, out_pixels, width / 3);

                        // Test CMYK conversions (if we have CMYK data)
                        cupsImageCMYKToBlack(pixels, out_pixels, width / 4);
                        cupsImageCMYKToCMY(pixels, out_pixels, width / 4);
                        cupsImageCMYKToRGB(pixels, out_pixels, width / 4);
                        cupsImageCMYKToWhite(pixels, out_pixels, width / 4);

                        // Test White conversions
                        cupsImageWhiteToBlack(pixels, out_pixels, width);
                        cupsImageWhiteToCMY(pixels, out_pixels, width);
                        cupsImageWhiteToCMYK(pixels, out_pixels, width);
                        cupsImageWhiteToRGB(pixels, out_pixels, width);

                        free(out_pixels);
                    }
                }

                // Test RGB adjustment and LUT
                cupsImageRGBAdjust(pixels, width, 50, 25);

                // Test LUT application
                cups_ib_t lut[256];
                for (int i = 0; i < 256; i++)
                {
                    lut[i] = 255 - i; // Invert LUT
                }
                cupsImageLut(pixels, width * 3, lut);

                free(pixels);
            }
        }

        // Test cropping if image is large enough
        if (width > 10 && height > 10)
        {
            cups_image_t *cropped = cupsImageCrop(img, 2, 2, width / 2, height / 2);
            if (cropped)
            {
                cupsImageClose(cropped);
            }
        }

        cupsImageClose(img);
    }

    // Test with different colorspace combinations
    img = cupsImageOpen(input_file, CUPS_IMAGE_WHITE, CUPS_IMAGE_RGB, 90, 10, NULL);
    if (img)
    {
        cupsImageClose(img);
    }

    img = cupsImageOpen(input_file, CUPS_IMAGE_CMYK, CUPS_IMAGE_RGB, 75, 45, NULL);
    if (img)
    {
        cupsImageClose(img);
    }

    // Cleanup
    unlink(input_file);

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
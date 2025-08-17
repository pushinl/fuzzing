//
// Dither test program for cups-filters.
//
// Try the following:
//
//       testdither 0 255 > filename.ppm
//       testdither 0 127 255 > filename.ppm
//       testdither 0 85 170 255 > filename.ppm
//       testdither 0 63 127 170 198 227 255 > filename.ppm
//       testdither 0 210 383 > filename.ppm
//       testdither 0 82 255 > filename.ppm
//
// Copyright 2007-2011 by Apple Inc.
// Copyright 1993-2005 by Easy Software Products.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//
// Contents:
//
//   main()  - Test dithering and output a PPM file.
//

//
// Include necessary headers.
//

#include "../cupsfilters/driver.h"
#include <string.h>
#include <ctype.h>

static void redirect_stdout_stderr(); // hide stdout

// fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{

    if (Size < 4)
    {
        return 0;
    }

    redirect_stdout_stderr();

    int x, y;                  // Current coordinate in image
    short line[512];           // Line to dither
    unsigned char pixels[512], // Dither pixels
        *pixptr;               // Pointer in line
    int output;                // Output pixel
    cups_lut_t *lut;           // Dither lookup table
    cups_dither_t *dither;     // Dither state
    int nlutvals;              // Number of lookup values
    float lutvals[16];         // Lookup values
    int pixvals[16];           // Pixel values

    int argc = (Data[0] % 10) + 2;

    if (Size < (size_t)(argc + 1))
    {
        return 0;
    }

    char **argv = (char **)malloc(argc * sizeof(char *));
    if (!argv)
    {
        return 0;
    }

    for (int i = 0; i < argc; i++)
    {
        if (Size < (i + 1))
        {
            break;
        }

        int num = abs((int)Data[i % Size]);
        argv[i] = (char *)malloc(12);
        if (!argv[i])
        {
            for (int j = 0; j < i; j++)
            {
                if (argv[j])
                    free(argv[j]);
            }
            free(argv);
            return 0;
        }
        snprintf(argv[i], 12, "%d", num);
    }

    //
    // See if we have lookup table values on the command-line...
    //

    if (argc > 1)
    {
        //
        // Yes, collect them...
        //

        nlutvals = 0;

        for (x = 1; x < argc; x++)
            if (isdigit(argv[x][0]) && nlutvals < 16)
            {
                pixvals[nlutvals] = atoi(argv[x]);
                lutvals[nlutvals] = atof(argv[x]) / 255.0;
                nlutvals++;
            }
            else
            {
                for (int j = 0; j < argc; j++)
                {
                    if (argv[j])
                        free(argv[j]);
                }
                free(argv);
                return 0;
            }

        //
        // See if we have at least 2 values...
        //

        if (nlutvals < 2)
        {
            for (int j = 0; j < argc; j++)
            {
                if (argv[j])
                    free(argv[j]);
            }
            free(argv);
            return 0;
        }
    }
    else
    {
        //
        // Otherwise use the default 2-entry LUT with values of 0 and 255...
        //

        nlutvals = 2;
        lutvals[0] = 0.0;
        lutvals[1] = 1.0;
        pixvals[0] = 0;
        pixvals[1] = 255;
    }

    //
    // Create the lookup table and dither state...
    //

    lut = cupsLutNew(nlutvals, lutvals);
    dither = cupsDitherNew(512);

    if (!lut || !dither)
    {
        if (lut)
            cupsLutDelete(lut);
        if (dither)
            cupsDitherDelete(dither);
        for (int j = 0; j < argc; j++)
        {
            if (argv[j])
                free(argv[j]);
        }
        free(argv);
        return 0;
    }

    //
    // Dither 512 lines, which are written out in 256 image lines...
    //

    for (y = 0; y < 256; y++)
    {
        //
        // Create the grayscale data for the current line...
        //

        for (x = 0; x < 512; x++)
            line[x] = 4095 * ((y / 32) * 16 + x / 32) / 255;

        //
        // Dither the line...
        //

        cupsDitherLine(dither, lut, line, 1, pixels);

        //
        // Add or set the output pixel values...
        //

        for (x = 0, pixptr = pixels; x < 512; x++, pixptr++)
        {
            output = 255 - pixvals[*pixptr];

            if (output < 0)
                output = 0;
            else if (output > 255)
                output = 255;

            // Don't actually output to avoid large outputs
            (void)output;
        }
    }

    //
    // Free the dither state and lookup table...
    //

    cupsDitherDelete(dither);
    cupsLutDelete(lut);

    //
    // Return with no errors...
    //

    for (int j = 0; j < argc; j++)
    {
        if (argv[j])
            free(argv[j]);
    }
    free(argv);
    return (0);
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

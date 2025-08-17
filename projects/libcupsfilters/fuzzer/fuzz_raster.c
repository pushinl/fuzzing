//
// Raster processing fuzzer for libcupsfilters
//
// Test cfRasterPrepareHeader, cfRasterColorSpaceString, and related functions
//
// Copyright 2024
//
// Licensed under Apache License v2.0. See the file "LICENSE" for more
// information.
//

#include "raster.h"
#include "filter.h"
#include "driver.h"
#include <config.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <cups/cups.h>
#include <cups/raster.h>

cf_logfunc_t logfunc = cfCUPSLogFunc; // Log function
void *ld = NULL;                      // Log function data

// Test raster processing functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 50 || Size > 100000)
    {
        return 0;
    }

    // Redirect output to temporary file
    freopen("/tmp/fuzz_raster_test", "w", stdout);
    freopen("/tmp/fuzz_raster_test", "w", stderr);

    // Create filter data structure
    cf_filter_data_t data;
    memset(&data, 0, sizeof(data));
    data.printer = "test-printer";
    data.job_id = 1;
    data.job_user = "testuser";
    data.job_title = "test-job";
    data.copies = 1;
    data.content_type = "image/pwg-raster";
    data.final_content_type = "image/vnd.cups-raster";
    data.logfunc = logfunc;
    data.logdata = ld;

    // Create and initialize page header
    cups_page_header_t header;
    memset(&header, 0, sizeof(header));

    // Set basic header fields from fuzzer data
    header.MediaClass[0] = '\0';
    header.MediaColor[0] = '\0';
    header.MediaType[0] = '\0';
    header.OutputType[0] = '\0';
    header.AdvanceDistance = 0;
    header.AdvanceMedia = CUPS_ADVANCE_NONE;
    header.Collate = CUPS_FALSE;
    header.CutMedia = CUPS_CUT_NONE;
    header.Duplex = CUPS_FALSE;

    // Use fuzzer data to set dimensions and resolution
    header.HWResolution[0] = ((Data[0] << 8) | Data[1]) % 1200 + 72; // 72-1271 DPI
    header.HWResolution[1] = ((Data[2] << 8) | Data[3]) % 1200 + 72; // 72-1271 DPI
    header.PageSize[0] = ((Data[4] << 8) | Data[5]) % 1000 + 100;    // 100-1099 points
    header.PageSize[1] = ((Data[6] << 8) | Data[7]) % 1000 + 100;    // 100-1099 points

    // Set margins from fuzzer data
    header.Margins[0] = Data[8] % 100; // Left margin
    header.Margins[1] = Data[9] % 100; // Bottom margin

    // Set color space and other parameters
    cups_cspace_t colorspaces[] = {
        CUPS_CSPACE_W,       // Grayscale
        CUPS_CSPACE_RGB,     // sRGB
        CUPS_CSPACE_CMYK,    // CMYK
        CUPS_CSPACE_K,       // Black
        CUPS_CSPACE_CIELab,  // CIE Lab
        CUPS_CSPACE_DEVICE1, // Device specific
        CUPS_CSPACE_DEVICE2, // Device specific
        CUPS_CSPACE_DEVICE3  // Device specific
    };

    header.cupsColorSpace = colorspaces[Data[10] % 8];
    header.cupsBitsPerColor = (Data[11] % 3) * 8 + 1; // 1, 8, or 16 bits
    header.cupsBitsPerPixel = header.cupsBitsPerColor * ((header.cupsColorSpace == CUPS_CSPACE_RGB) ? 3 : (header.cupsColorSpace == CUPS_CSPACE_CMYK) ? 4
                                                                                                                                                      : 1);
    header.cupsBytesPerLine = (header.PageSize[0] * header.cupsBitsPerPixel + 7) / 8;
    header.cupsHeight = header.PageSize[1];
    header.cupsWidth = header.PageSize[0];

    // Test color space string function
    for (int cs = 0; cs < 8; cs++)
    {
        const char *cs_string = cfRasterColorSpaceString(colorspaces[cs]);
        (void)cs_string; // Suppress unused warning
    }

    // Test with invalid color space
    const char *invalid_cs = cfRasterColorSpaceString((cups_cspace_t)999);
    (void)invalid_cs;

    // Test raster header preparation with different output formats
    cf_filter_out_format_t output_formats[] = {
        CF_FILTER_OUT_FORMAT_PDF,
        CF_FILTER_OUT_FORMAT_CUPS_RASTER,
        CF_FILTER_OUT_FORMAT_PWG_RASTER,
        CF_FILTER_OUT_FORMAT_APPLE_RASTER,
        CF_FILTER_OUT_FORMAT_PXL};

    cf_filter_out_format_t header_formats[] = {
        CF_FILTER_OUT_FORMAT_CUPS_RASTER,
        CF_FILTER_OUT_FORMAT_PWG_RASTER,
        CF_FILTER_OUT_FORMAT_APPLE_RASTER};

    for (int of = 0; of < 5; of++)
    {
        for (int hf = 0; hf < 3; hf++)
        {
            cups_page_header_t test_header = header;
            cups_cspace_t cspace;

            // Test without high depth restriction
            int result1 = cfRasterPrepareHeader(&test_header, &data,
                                                output_formats[of],
                                                header_formats[hf],
                                                0, &cspace);
            (void)result1;
            (void)cspace;

            // Test with high depth restriction
            test_header = header;
            int result2 = cfRasterPrepareHeader(&test_header, &data,
                                                output_formats[of],
                                                header_formats[hf],
                                                1, &cspace);
            (void)result2;
        }
    }

    // Test with various color spaces in the header
    for (int cs = 0; cs < 8; cs++)
    {
        cups_page_header_t cs_header = header;
        cs_header.cupsColorSpace = colorspaces[cs];

        // Adjust bits per pixel based on color space
        switch (colorspaces[cs])
        {
        case CUPS_CSPACE_RGB:
            cs_header.cupsBitsPerPixel = cs_header.cupsBitsPerColor * 3;
            break;
        case CUPS_CSPACE_CMYK:
            cs_header.cupsBitsPerPixel = cs_header.cupsBitsPerColor * 4;
            break;
        default:
            cs_header.cupsBitsPerPixel = cs_header.cupsBitsPerColor;
            break;
        }
        cs_header.cupsBytesPerLine = (cs_header.cupsWidth * cs_header.cupsBitsPerPixel + 7) / 8;

        cups_cspace_t out_cspace;
        int result = cfRasterPrepareHeader(&cs_header, &data,
                                           CF_FILTER_OUT_FORMAT_PWG_RASTER,
                                           CF_FILTER_OUT_FORMAT_PWG_RASTER,
                                           0, &out_cspace);
        (void)result;
        (void)out_cspace;
    }

    // Test with edge case dimensions
    cups_page_header_t edge_header = header;

    // Very small dimensions
    edge_header.PageSize[0] = 1;
    edge_header.PageSize[1] = 1;
    edge_header.cupsWidth = 1;
    edge_header.cupsHeight = 1;
    edge_header.cupsBytesPerLine = 1;

    cups_cspace_t edge_cspace;
    int edge_result = cfRasterPrepareHeader(&edge_header, &data,
                                            CF_FILTER_OUT_FORMAT_PWG_RASTER,
                                            CF_FILTER_OUT_FORMAT_PWG_RASTER,
                                            0, &edge_cspace);
    (void)edge_result;
    (void)edge_cspace;

    // Test with different bit depths
    int bit_depths[] = {1, 8, 16};
    for (int bd = 0; bd < 3; bd++)
    {
        cups_page_header_t bd_header = header;
        bd_header.cupsBitsPerColor = bit_depths[bd];
        bd_header.cupsBitsPerPixel = bd_header.cupsBitsPerColor * 3; // RGB
        bd_header.cupsBytesPerLine = (bd_header.cupsWidth * bd_header.cupsBitsPerPixel + 7) / 8;

        cups_cspace_t bd_cspace;
        int bd_result = cfRasterPrepareHeader(&bd_header, &data,
                                              CF_FILTER_OUT_FORMAT_CUPS_RASTER,
                                              CF_FILTER_OUT_FORMAT_CUPS_RASTER,
                                              0, &bd_cspace);
        (void)bd_result;
        (void)bd_cspace;
    }

    // Test with fuzzer-controlled parameters
    if (Size > 30)
    {
        cups_page_header_t fuzz_header = header;

        // Use more fuzzer data for header parameters
        fuzz_header.HWResolution[0] = ((Data[20] << 8) | Data[21]) % 2400 + 72;
        fuzz_header.HWResolution[1] = ((Data[22] << 8) | Data[23]) % 2400 + 72;
        fuzz_header.PageSize[0] = ((Data[24] << 8) | Data[25]) % 2000 + 50;
        fuzz_header.PageSize[1] = ((Data[26] << 8) | Data[27]) % 2000 + 50;
        fuzz_header.cupsWidth = fuzz_header.PageSize[0];
        fuzz_header.cupsHeight = fuzz_header.PageSize[1];

        // Randomize color space and bit depth
        fuzz_header.cupsColorSpace = colorspaces[Data[28] % 8];
        fuzz_header.cupsBitsPerColor = ((Data[29] % 3) + 1) * 8; // 8, 16, or 24 bits

        // Calculate dependent fields
        int channels = (fuzz_header.cupsColorSpace == CUPS_CSPACE_RGB) ? 3 : (fuzz_header.cupsColorSpace == CUPS_CSPACE_CMYK) ? 4
                                                                                                                              : 1;
        fuzz_header.cupsBitsPerPixel = fuzz_header.cupsBitsPerColor * channels;
        fuzz_header.cupsBytesPerLine = (fuzz_header.cupsWidth * fuzz_header.cupsBitsPerPixel + 7) / 8;

        cups_cspace_t fuzz_cspace;
        int fuzz_result = cfRasterPrepareHeader(&fuzz_header, &data,
                                                output_formats[Data[30] % 5],
                                                header_formats[Data[31] % 3],
                                                Data[32] % 2, &fuzz_cspace);
        (void)fuzz_result;
        (void)fuzz_cspace;
    }

    // Cleanup
    fclose(stdout);
    fclose(stderr);

    return 0;
}

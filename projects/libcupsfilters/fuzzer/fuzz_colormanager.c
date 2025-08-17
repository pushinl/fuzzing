//
// Color manager fuzzer for libcupsfilters
//
// Test color management functions like cfCmGetPrinterIccProfile, cfCmIsPrinterCmDisabled, etc.
//
// Copyright 2024
//
// Licensed under Apache License v2.0. See the file "LICENSE" for more
// information.
//

#include "colormanager.h"
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

cf_logfunc_t logfunc = cfCUPSLogFunc; // Log function
void *ld = NULL;                      // Log function data

// Test color management functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 20 || Size > 50000)
    {
        return 0;
    }

    // Redirect output to temporary file
    freopen("/tmp/fuzz_cm_test", "w", stdout);
    freopen("/tmp/fuzz_cm_test", "w", stderr);

    // Create filter data structure
    cf_filter_data_t data;
    memset(&data, 0, sizeof(data));

    // Set up basic filter data
    data.printer = "test-printer";
    data.job_id = 1;
    data.job_user = "testuser";
    data.job_title = "test-job";
    data.copies = 1;
    data.logfunc = logfunc;
    data.logdata = ld;

    // Create some sample options from fuzzer data
    int num_options = (Data[0] % 10) + 1;
    cups_option_t *options = NULL;

    // Add some color-related options
    char option_name[64];
    char option_value[128];

    for (int i = 0; i < num_options && (i * 20 + 20) < Size; i++)
    {
        // Generate option names and values from fuzzer data
        snprintf(option_name, sizeof(option_name), "ColorModel");
        snprintf(option_value, sizeof(option_value), "RGB");

        if (Data[i * 2] % 2)
        {
            snprintf(option_name, sizeof(option_name), "cm-calibration");
            snprintf(option_value, sizeof(option_value), "on");
        }

        options = cupsAddOption(option_name, option_value, num_options, &options);
    }

    data.num_options = num_options;
    data.options = options;

    // Test color calibration mode detection
    cf_cm_calibration_t calibration = cfCmGetCupsColorCalibrateMode(&data);
    (void)calibration; // Suppress unused warning

    // Test printer color management disable check
    int cm_disabled = cfCmIsPrinterCmDisabled(&data);
    (void)cm_disabled;

    // Test ICC profile retrieval with various parameters
    char *icc_profile = NULL;

    // Test with different color spaces
    const char *color_spaces[] = {"RGB", "CMYK", "Gray", "sRGB"};
    const char *media_types[] = {"plain", "photo", "glossy", "matte"};

    for (int cs = 0; cs < 4; cs++)
    {
        for (int mt = 0; mt < 4; mt++)
        {
            int x_res = (Data[cs * 4 + mt + 1] % 600) + 72; // 72-671 DPI
            int y_res = (Data[cs * 4 + mt + 2] % 600) + 72; // 72-671 DPI

            int result = cfCmGetPrinterIccProfile(&data,
                                                  color_spaces[cs],
                                                  media_types[mt],
                                                  x_res, y_res,
                                                  &icc_profile);
            (void)result;

            if (icc_profile)
            {
                free(icc_profile);
                icc_profile = NULL;
            }
        }
    }

    // Test color space matrix and gamma functions
    double *gamma_adobe = cfCmGammaAdobeRGB();
    double *gamma_sgray = cfCmGammaSGray();
    double *white_adobe = cfCmWhitePointAdobeRGB();
    double *white_sgray = cfCmWhitePointSGray();
    double *matrix_adobe = cfCmMatrixAdobeRGB();
    double *black_default = cfCmBlackPointDefault();

    // Use the returned values to prevent optimization
    (void)gamma_adobe;
    (void)gamma_sgray;
    (void)white_adobe;
    (void)white_sgray;
    (void)matrix_adobe;
    (void)black_default;

    // Test with fuzzer-generated color space and media type strings
    if (Size > 40)
    {
        char fuzz_color_space[32];
        char fuzz_media_type[32];

        // Create null-terminated strings from fuzzer data
        int cs_len = (Data[20] % 20) + 1;
        int mt_len = (Data[21] % 20) + 1;

        for (int i = 0; i < cs_len && (22 + i) < Size; i++)
        {
            fuzz_color_space[i] = (Data[22 + i] % 94) + 32; // Printable ASCII
        }
        fuzz_color_space[cs_len] = '\0';

        for (int i = 0; i < mt_len && (22 + cs_len + i) < Size; i++)
        {
            fuzz_media_type[i] = (Data[22 + cs_len + i] % 94) + 32; // Printable ASCII
        }
        fuzz_media_type[mt_len] = '\0';

        int x_res = ((Data[23] << 8) | Data[24]) % 1200 + 72;
        int y_res = ((Data[25] << 8) | Data[26]) % 1200 + 72;

        int result = cfCmGetPrinterIccProfile(&data,
                                              fuzz_color_space,
                                              fuzz_media_type,
                                              x_res, y_res,
                                              &icc_profile);
        (void)result;

        if (icc_profile)
        {
            free(icc_profile);
            icc_profile = NULL;
        }
    }

    // Test with additional calibration-related options
    if (Size > 50)
    {
        char cal_option[64];
        char cal_value[64];

        snprintf(cal_option, sizeof(cal_option), "Calibrate");
        snprintf(cal_value, sizeof(cal_value), "%d", Data[30] % 2);
        options = cupsAddOption(cal_option, cal_value, data.num_options, &options);
        data.num_options++;

        snprintf(cal_option, sizeof(cal_option), "ColorProfile");
        snprintf(cal_value, sizeof(cal_value), "sRGB");
        options = cupsAddOption(cal_option, cal_value, data.num_options, &options);
        data.num_options++;

        data.options = options;

        // Re-test with new options
        calibration = cfCmGetCupsColorCalibrateMode(&data);
        cm_disabled = cfCmIsPrinterCmDisabled(&data);
        (void)calibration;
        (void)cm_disabled;
    }

    // Cleanup
    if (options)
    {
        cupsFreeOptions(data.num_options, options);
    }

    fclose(stdout);
    fclose(stderr);

    return 0;
}

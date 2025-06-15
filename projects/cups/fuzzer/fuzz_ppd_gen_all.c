#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "ppd.h"
#include "cups.h"
#include "ipp.h"
#include "pwg.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a temporary file name using process ID to avoid conflicts
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());

    // Write the input data to the temporary file
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (!ppd) {
        unlink(filename);
        return 0;
    }

    // Perform various operations
    ppd_attr_t *attr = ppdFindAttr(ppd, "DefaultColorSpace", NULL);
    while (attr) {
        attr = ppdFindNextAttr(ppd, "DefaultColorSpace", NULL);
    }

    ppdLocalize(ppd);
    char buffer[256];
    ppdLocalizeIPPReason(ppd, "reason", "scheme", buffer, sizeof(buffer));
    ppdLocalizeMarkerName(ppd, "marker");

    ppdMarkDefaults(ppd);
    ppdConflicts(ppd);

    cups_option_t *options = NULL;
    int num_options = cupsParseOptions("option=value", 0, &options);
    cupsMarkOptions(ppd, num_options, options);
    cupsGetConflicts(ppd, "option", "choice", &options);
    cupsResolveConflicts(ppd, "option", "choice", &num_options, &options);
    cupsFreeOptions(num_options, options);

    ppdMarkOption(ppd, "name", "value");
    ppdFindMarkedChoice(ppd, "option");

    cupsGetOption("name", num_options, options);
    ppdInstallableConflict(ppd, "option", "choice");

    ppd_size_t *size_limits = ppdPageSize(ppd, "A4");
    ppdPageWidth(ppd, "A4");
    ppdPageLength(ppd, "A4");
    ppdPageSizeLimits(ppd, NULL, NULL);
    ppdEmitString(ppd, PPD_ORDER_ANY, 0.0);

    pwgMediaForSize(21000, 29700);

    // Cache operations
    ipp_t *attrs = ippNew();
    _ppd_cache_t *cache = _ppdCacheCreateWithPPD(attrs, ppd);
    if (cache) {
        _ppdCacheWriteFile(cache, filename, attrs);
        _ppdCacheGetBin(cache, "output_bin");
        int exact;
        _ppdCacheGetPageSize(cache, attrs, "option", &exact);
        _ppdCacheDestroy(cache);
    }
    ippDelete(attrs);

    // Close the PPD file
    ppdClose(ppd);

    // Clean up the temporary file
    unlink(filename);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ppd.h"
#include "cups.h"
#include "pwg.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there is at least some data

    // Create a temporary file to use with ppdOpenFile
    char filename[] = "/tmp/fuzz_ppd_XXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) return 0;

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(filename);
        return 0;
    }
    close(fd);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (ppd) {
        // Fuzz ppdPageSize
        ppd_size_t *size = ppdPageSize(ppd, "A4");

        // Fuzz ppdPageWidth and ppdPageLength
        float width = ppdPageWidth(ppd, "A4");
        float length = ppdPageLength(ppd, "A4");

        // Fuzz ppdPageSizeLimits
        ppd_size_t min, max;
        ppdPageSizeLimits(ppd, &min, &max);

        // Fuzz ppdEmitString
        ppdEmitString(ppd, PPD_ORDER_ANY, 0.0f);

        // Close the PPD file
        ppdClose(ppd);
    }

    // Clean up the temporary file
    unlink(filename);

    // Fuzz pwgMediaForSize independently
    if (size >= 8) { // Ensure we have enough data for two integers
        int width = *((int *)data);
        int length = *((int *)(data + 4));
        const char *media = pwgMediaForSize(width, length);
    }

    return 0;
}

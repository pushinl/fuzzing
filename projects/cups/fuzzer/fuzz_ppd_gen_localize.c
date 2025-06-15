#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ppd.h"
#include "cups.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a unique temporary file name using the process ID
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());

    // Write the input data to a temporary file
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (ppd) {
        // Localize the PPD file
        ppdLocalize(ppd);

        // Find an attribute
        ppd_attr_t *attr = ppdFindAttr(ppd, "PageSize", NULL);
        while (attr) {
            // Find next attribute
            attr = ppdFindNextAttr(ppd, "PageSize", NULL);
        }

        // Localize IPP Reason
        char buffer[256];
        ppdLocalizeIPPReason(ppd, "reason", "scheme", buffer, sizeof(buffer));

        // Localize Marker Name
        ppdLocalizeMarkerName(ppd, "marker-name");

        // Close the PPD file
        ppdClose(ppd);
    }

    // Remove the temporary file
    unlink(filename);

    return 0;
}

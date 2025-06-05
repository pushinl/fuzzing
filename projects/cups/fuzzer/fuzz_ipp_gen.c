#include <stdio.h>
#include <string.h>
#include <ipp.h>
#include <cups/cups.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parameters for ippReadIO
    void *buffer = (void *)data;
    int flags = 0;

    ipp_t *request = ippNew();       // Create a new ipp_t object for request
    ipp_t *response = ippNew();      // Create a new ipp_t object for response

    // Parameters for cupsFileOpen and cupsFileClose
    char filename[256];
    const char *mode = "rw"; // Open for reading
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    cups_file_t *file = cupsFileOpen(filename, mode);

    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return 0; // Exit if file opening failed
    }

    // Call the function under test
    ippReadIO(buffer, (ipp_iocb_t)cupsFileRead, flags, request, response);

    // Close the file
    cupsFileClose(file);
    ippDelete(request);
    ippDelete(response);

    
    return 0;
}

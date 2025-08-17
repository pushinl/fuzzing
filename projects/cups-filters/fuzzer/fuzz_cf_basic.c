#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include "cupsfilters/filter.h"
#include "ppd/ppd-filter.h"

// Mock filter function for ppdFilterCUPSWrapper
int mock_filter_func(int inputfd, int outputfd, int inputseekable, cf_filter_data_t *data, void *parameters)
{
    // For simplicity, just call one of the filter functions directly
    return cfFilterTextToPDF(inputfd, outputfd, inputseekable, data, parameters);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0; // Ensure there's at least some data

    // Create temporary files for input and output
    char input_filename[256], output_filename[256];
    snprintf(input_filename, sizeof(input_filename), "/tmp/input_%d.txt", getpid());
    snprintf(output_filename, sizeof(output_filename), "/tmp/output_%d.txt", getpid());

    int inputfd = open(input_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    int outputfd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

    if (inputfd < 0 || outputfd < 0)
    {
        perror("Failed to open temporary files");
        return 0;
    }

    // Write fuzz data to input file
    write(inputfd, data, size);
    lseek(inputfd, 0, SEEK_SET); // Reset file pointer to the beginning

    // Prepare filter data and parameters
    cf_filter_data_t filter_data = {0};
    void *parameters = NULL;
    int job_canceled = 0;

    // Prepare arguments for ppdFilterCUPSWrapper
    char *argv[] = {"fuzz_program", input_filename, output_filename};
    int argc = 3;

    // Call ppdFilterCUPSWrapper with a mock filter function
    ppdFilterCUPSWrapper(argc, argv, mock_filter_func, parameters, &job_canceled);

    // Clean up
    close(inputfd);
    close(outputfd);
    unlink(input_filename);
    unlink(output_filename);

    return 0;
}

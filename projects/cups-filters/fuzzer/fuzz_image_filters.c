#include <cupsfilters/filter.h>
#include <ppd/ppd-filter.h>
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
    lseek(input_fd, 0, SEEK_SET);

    // Create temporary output file
    char output_file[] = "/tmp/fuzz_image_output_XXXXXX";
    int output_fd = mkstemp(output_file);
    if (output_fd < 0)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }

    // Setup filter data structure
    cf_filter_data_t data;
    memset(&data, 0, sizeof(data));
    data.printer = "test-printer";
    data.job_id = 1;
    data.job_user = "testuser";
    data.job_title = "test-job";
    data.copies = 1;
    data.content_type = "image/jpeg";
    data.final_content_type = "application/pdf";
    data.job_attrs = NULL;
    data.printer_attrs = NULL;
    data.header = NULL;
    data.num_options = 0;
    data.options = NULL;
    data.back_pipe[0] = -1;
    data.back_pipe[1] = -1;
    data.side_pipe[0] = -1;
    data.side_pipe[1] = -1;
    data.extension = NULL;
    data.logfunc = NULL;
    data.logdata = NULL;
    data.iscanceledfunc = NULL;
    data.iscanceleddata = NULL;

    // Test ppdFilterImageToPDF with different image types
    int result = ppdFilterImageToPDF(input_fd, output_fd, 1, &data, NULL);
    (void)result; // Suppress unused variable warning

    // Reset file positions and test PNG
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/png";
    result = ppdFilterImageToPDF(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test TIFF
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/tiff";
    result = ppdFilterImageToPDF(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test ppdFilterImageToPS
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/jpeg";
    data.final_content_type = "application/postscript";
    result = ppdFilterImageToPS(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test cfFilterImageToRaster
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/jpeg";
    data.final_content_type = "image/pwg-raster";
    result = cfFilterImageToRaster(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test with PNG
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/png";
    result = cfFilterImageToRaster(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test with TIFF
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/tiff";
    result = cfFilterImageToRaster(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Cleanup
    close(input_fd);
    close(output_fd);
    unlink(input_file);
    unlink(output_file);

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
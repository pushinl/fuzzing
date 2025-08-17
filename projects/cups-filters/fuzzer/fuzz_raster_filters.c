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

// Test raster processing functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 1000000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary input file
    char input_file[] = "/tmp/fuzz_raster_input_XXXXXX";
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
    char output_file[] = "/tmp/fuzz_raster_output_XXXXXX";
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
    data.content_type = "image/pwg-raster";
    data.final_content_type = "image/vnd.cups-raster";
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

    // Test cfFilterPWGToRaster
    int result = cfFilterPWGToRaster(input_fd, output_fd, 1, &data, NULL);
    (void)result; // Suppress unused variable warning

    // Reset file positions
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);

    // Test cfFilterRasterToPWG
    data.content_type = "image/vnd.cups-raster";
    data.final_content_type = "image/pwg-raster";
    result = cfFilterRasterToPWG(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test cfFilterPWGToPDF
    data.content_type = "image/pwg-raster";
    data.final_content_type = "application/pdf";
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    cf_filter_out_format_t outformat = CF_FILTER_OUT_FORMAT_PDF;
    result = cfFilterPWGToPDF(input_fd, output_fd, 1, &data, &outformat);
    (void)result;

    // Test cfFilterPWGToPDF with PCLM output
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    outformat = CF_FILTER_OUT_FORMAT_PCLM;
    data.final_content_type = "application/vnd.hp-pclm";
    result = cfFilterPWGToPDF(input_fd, output_fd, 1, &data, &outformat);
    (void)result;

    // Test ppdFilterRasterToPS
    data.content_type = "image/vnd.cups-raster";
    data.final_content_type = "application/postscript";
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    result = ppdFilterRasterToPS(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test cfFilterMuPDFToPWG
    data.content_type = "application/pdf";
    data.final_content_type = "image/pwg-raster";
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    result = cfFilterMuPDFToPWG(input_fd, output_fd, 1, &data, NULL);
    (void)result;

    // Test cfFilterPCLmToRaster
    data.content_type = "application/vnd.hp-pclm";
    data.final_content_type = "image/pwg-raster";
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    outformat = CF_FILTER_OUT_FORMAT_PWG_RASTER;
    result = cfFilterPCLmToRaster(input_fd, output_fd, 1, &data, &outformat);
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

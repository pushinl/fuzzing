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

// Test cfFilterUniversal and related chain functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 200000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary input file
    char input_file[] = "/tmp/fuzz_universal_input_XXXXXX";
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
    char output_file[] = "/tmp/fuzz_universal_output_XXXXXX";
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
    data.content_type = "text/plain";
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

    // Test cfFilterUniversal with various content types
    cf_filter_universal_parameter_t universal_params;
    memset(&universal_params, 0, sizeof(universal_params));
    universal_params.actual_output_type = "application/pdf";
    universal_params.texttopdf_params.data_dir = "/usr/share/cups/data";
    universal_params.texttopdf_params.char_set = "utf-8";
    universal_params.texttopdf_params.content_type = "text/plain";
    universal_params.texttopdf_params.classification = NULL;
    universal_params.bannertopdf_template_dir = "/usr/share/cups/data";

    int result = cfFilterUniversal(input_fd, output_fd, 1, &data, &universal_params);
    (void)result; // Suppress unused variable warning

    // Test with different input content types
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "application/pdf";
    universal_params.actual_output_type = "application/postscript";
    data.final_content_type = "application/postscript";
    result = cfFilterUniversal(input_fd, output_fd, 1, &data, &universal_params);
    (void)result;

    // Test with image input
    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    data.content_type = "image/jpeg";
    universal_params.actual_output_type = "application/pdf";
    data.final_content_type = "application/pdf";
    result = cfFilterUniversal(input_fd, output_fd, 1, &data, &universal_params);
    (void)result;

    // Test cfFilterTee function
    char tee_file[] = "/tmp/fuzz_tee_XXXXXX";
    int tee_fd = mkstemp(tee_file);
    if (tee_fd >= 0)
    {
        close(tee_fd);
        lseek(input_fd, 0, SEEK_SET);
        lseek(output_fd, 0, SEEK_SET);
        result = cfFilterTee(input_fd, output_fd, 1, &data, tee_file);
        (void)result;
        unlink(tee_file);
    }

    // Test cfFilterExternal (if we have external filters available)
    cf_filter_external_t external_params;
    memset(&external_params, 0, sizeof(external_params));
    external_params.filter = "/bin/cat";
    external_params.exec_mode = 0;
    external_params.num_options = 0;
    external_params.options = NULL;
    external_params.envp = NULL;

    lseek(input_fd, 0, SEEK_SET);
    lseek(output_fd, 0, SEEK_SET);
    result = cfFilterExternal(input_fd, output_fd, 1, &data, &external_params);
    (void)result;

    // Test filter chain functionality
    // Create a simple filter chain
    cups_array_t *filter_chain = cupsArrayNew(NULL, NULL);
    if (filter_chain)
    {
        cf_filter_filter_in_chain_t filter1;
        memset(&filter1, 0, sizeof(filter1));
        filter1.function = cfFilterTextToPDF;
        filter1.parameters = &universal_params.texttopdf_params;
        filter1.name = "texttopdf";

        cupsArrayAdd(filter_chain, &filter1);

        lseek(input_fd, 0, SEEK_SET);
        lseek(output_fd, 0, SEEK_SET);
        data.content_type = "text/plain";
        data.final_content_type = "application/pdf";
        result = cfFilterChain(input_fd, output_fd, 1, &data, filter_chain);
        (void)result;

        cupsArrayDelete(filter_chain);
    }

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

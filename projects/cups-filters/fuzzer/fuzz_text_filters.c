#include "pdfutils.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void redirect_stdout_stderr();

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 5 || Size > 100000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary input file
    char input_file[] = "/tmp/fuzz_text_input_XXXXXX";
    int input_fd = mkstemp(input_file);
    if (input_fd < 0)
    {
        return 0;
    }

    // Write fuzzer input to temporary file
    if (write(input_fd, Data, Size) != (ssize_t)Size)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }
    close(input_fd);

    // Create temporary output file
    char output_file[] = "/tmp/fuzz_text_output_XXXXXX";
    int output_fd = mkstemp(output_file);
    if (output_fd < 0)
    {
        unlink(input_file);
        return 0;
    }

    // Test 1: Text to PDF conversion using pdfOut
    pdfOut *pdf = pdfOut_new();
    if (pdf)
    {
        pdfOut_begin_pdf(pdf);

        // Add font
        int font_obj = pdfOut_add_xref(pdf);
        pdfOut_printf(pdf, "%d 0 obj\n"
                           "<</Type/Font\n"
                           "  /Subtype /Type1\n"
                           "  /BaseFont /Courier\n"
                           ">>\n"
                           "endobj\n",
                      font_obj);

        // Add content stream
        int content_obj = pdfOut_add_xref(pdf);
        char *text_buf = (char *)malloc(Size + 1);
        if (text_buf)
        {
            memcpy(text_buf, Data, Size);
            text_buf[Size] = '\0';

            // Sanitize text for PDF
            for (size_t i = 0; i < Size; i++)
            {
                if (text_buf[i] < 32 && text_buf[i] != '\n' && text_buf[i] != '\r' && text_buf[i] != '\t')
                {
                    text_buf[i] = ' ';
                }
            }

            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length %d\n"
                               ">>\n"
                               "stream\n"
                               "BT\n"
                               "/F1 12 Tf\n"
                               "50 750 Td\n"
                               "(%s) Tj\n"
                               "ET\n"
                               "endstream\n"
                               "endobj\n",
                          content_obj, (int)strlen(text_buf) + 50, text_buf);
            free(text_buf);
        }

        // Add page
        int page_obj = pdfOut_add_xref(pdf);
        pdfOut_printf(pdf, "%d 0 obj\n"
                           "<</Type/Page\n"
                           "  /Parent 1 0 R\n"
                           "  /MediaBox [0 0 595 842]\n"
                           "  /Contents %d 0 R\n"
                           "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                           ">>\n"
                           "endobj\n",
                      page_obj, content_obj, font_obj);

        pdfOut_add_page(pdf, page_obj);
        pdfOut_finish_pdf(pdf);
        pdfOut_free(pdf);
    }

    // Cleanup
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
        perror("Failed to open /dev/null");
        return;
    }
    dup2(dev_null, STDOUT_FILENO);
    dup2(dev_null, STDERR_FILENO);
    close(dev_null);
}

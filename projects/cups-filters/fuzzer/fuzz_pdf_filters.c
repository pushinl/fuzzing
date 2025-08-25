#include "pdfutils.h"
#include <cups/cups.h>
#include <cups/ppd.h>
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

// Test PDF utility functions (using the same pdfutils as fuzz_pdf.c)
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 10 || Size > 200000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Test pdfOut functions (similar to fuzz_pdf.c but with additional tests)
    pdfOut *pdf = pdfOut_new();
    if (!pdf)
    {
        return 0;
    }

    pdfOut_begin_pdf(pdf);

    // Create multiple objects to test PDF structure
    int font_obj = pdfOut_add_xref(pdf);
    pdfOut_printf(pdf, "%d 0 obj\n"
                       "<</Type/Font\n"
                       "  /Subtype /Type1\n"
                       "  /BaseFont /%s\n"
                       ">>\n"
                       "endobj\n",
                  font_obj, "Helvetica");

    // Test with fuzzer data as content
    char *buf = (char *)malloc(Size + 1);
    if (!buf)
    {
        pdfOut_free(pdf);
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Create content stream
    int content_obj = pdfOut_add_xref(pdf);
    pdfOut_printf(pdf, "%d 0 obj\n"
                       "<</Length %d\n"
                       ">>\n"
                       "stream\n"
                       "%s\n"
                       "endstream\n"
                       "endobj\n",
                  content_obj, (int)strlen(buf), buf);

    // Create page object
    const int PageWidth = 612, PageHeight = 792;
    int page_obj = pdfOut_add_xref(pdf);
    pdfOut_printf(pdf, "%d 0 obj\n"
                       "<</Type/Page\n"
                       "  /Parent 1 0 R\n"
                       "  /MediaBox [0 0 %d %d]\n"
                       "  /Contents %d 0 R\n"
                       "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                       ">>\n"
                       "endobj\n",
                  page_obj, PageWidth, PageHeight, content_obj, font_obj);

    pdfOut_add_page(pdf, page_obj);

    // Test creating multiple pages if we have enough data
    if (Size > 50)
    {
        int page2_content = pdfOut_add_xref(pdf);
        char *buf2 = strndup((char *)Data + 20, Size - 20 > 100 ? 100 : Size - 20);
        if (buf2)
        {
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length %d\n"
                               ">>\n"
                               "stream\n"
                               "BT /F1 12 Tf 72 720 Td (%s) Tj ET\n"
                               "endstream\n"
                               "endobj\n",
                          page2_content, (int)strlen(buf2) + 30, buf2);

            int page2_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Page\n"
                               "  /Parent 1 0 R\n"
                               "  /MediaBox [0 0 %d %d]\n"
                               "  /Contents %d 0 R\n"
                               "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                               ">>\n"
                               "endobj\n",
                          page2_obj, PageWidth, PageHeight, page2_content, font_obj);

            pdfOut_add_page(pdf, page2_obj);
            free(buf2);
        }
    }

    // Test different font types
    if (Size > 30)
    {
        int font2_obj = pdfOut_add_xref(pdf);
        pdfOut_printf(pdf, "%d 0 obj\n"
                           "<</Type/Font\n"
                           "  /Subtype /Type1\n"
                           "  /BaseFont /%s\n"
                           ">>\n"
                           "endobj\n",
                      font2_obj, "Times-Roman");
    }

    // Test with different page sizes
    if (Size > 40)
    {
        int page3_obj = pdfOut_add_xref(pdf);
        int custom_width = 200 + (Data[10] % 400);  // 200-599
        int custom_height = 200 + (Data[11] % 400); // 200-599

        pdfOut_printf(pdf, "%d 0 obj\n"
                           "<</Type/Page\n"
                           "  /Parent 1 0 R\n"
                           "  /MediaBox [0 0 %d %d]\n"
                           "  /Contents %d 0 R\n"
                           "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                           ">>\n"
                           "endobj\n",
                      page3_obj, custom_width, custom_height, content_obj, font_obj);

        pdfOut_add_page(pdf, page3_obj);
    }

    pdfOut_finish_pdf(pdf);
    pdfOut_free(pdf);
    free(buf);

    // Test with additional driver functions (color space testing)
    if (Size > 60)
    {
        int test_width = (Data[12] % 100) + 1;
        unsigned char *test_input = (unsigned char *)malloc(test_width * 3);
        unsigned char *test_output = (unsigned char *)malloc(test_width * 4);

        if (test_input && test_output)
        {
            // Fill with test data
            for (int i = 0; i < test_width * 3; i++)
            {
                test_input[i] = Data[(60 + i) % Size];
            }

            // Test byte checking
            int check_result = cupsCheckBytes(test_input, test_width * 3);
            (void)check_result;

            unsigned char check_val = Data[13] % 256;
            check_result = cupsCheckValue(test_input, test_width * 3, check_val);
            (void)check_result;
        }

        free(test_input);
        free(test_output);
    }

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
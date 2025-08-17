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
    if (Size < 8 || Size > 100000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary files for input/output
    char input_file[] = "/tmp/fuzz_universal_input_XXXXXX";
    char output_file[] = "/tmp/fuzz_universal_output_XXXXXX";

    int input_fd = mkstemp(input_file);
    int output_fd = mkstemp(output_file);

    if (input_fd < 0 || output_fd < 0)
    {
        if (input_fd >= 0)
            close(input_fd);
        if (output_fd >= 0)
            close(output_fd);
        return 0;
    }

    // Write input data
    if (write(input_fd, Data, Size) != (ssize_t)Size)
    {
        close(input_fd);
        close(output_fd);
        unlink(input_file);
        unlink(output_file);
        return 0;
    }
    close(input_fd);
    close(output_fd);

    // Universal filter testing through PDF conversion
    pdfOut *pdf = pdfOut_new();
    if (pdf)
    {
        pdfOut_begin_pdf(pdf);

        // Detect input format and process accordingly
        uint8_t format_hint = Data[0];

        if (format_hint < 64) // Text-like processing
        {
            char *text_content = (char *)malloc(Size + 1);
            if (text_content)
            {
                memcpy(text_content, Data, Size);
                text_content[Size] = '\0';

                // Sanitize text content
                for (size_t i = 0; i < Size; i++)
                {
                    if (text_content[i] < 32 && text_content[i] != '\n' && text_content[i] != '\r' && text_content[i] != '\t')
                    {
                        text_content[i] = ' ';
                    }
                }

                // Add font
                int font_obj = pdfOut_add_xref(pdf);
                pdfOut_printf(pdf, "%d 0 obj\n"
                                   "<</Type/Font\n"
                                   "  /Subtype/Type1\n"
                                   "  /BaseFont/Helvetica\n"
                                   ">>\n"
                                   "endobj\n",
                              font_obj);

                // Add text content
                int content_obj = pdfOut_add_xref(pdf);
                pdfOut_printf(pdf, "%d 0 obj\n"
                                   "<</Length %zu\n"
                                   ">>\n"
                                   "stream\n"
                                   "BT\n"
                                   "/F1 12 Tf\n"
                                   "50 750 Td\n"
                                   "(%s) Tj\n"
                                   "ET\n"
                                   "endstream\n"
                                   "endobj\n",
                              content_obj, strlen(text_content) + 50, text_content);

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
                free(text_content);
            }
        }
        else if (format_hint < 128) // Image-like processing
        {
            int img_obj = pdfOut_add_xref(pdf);

            // Determine color space based on data
            const char *colorspace = "/DeviceRGB";
            if (Data[1] % 3 == 1)
                colorspace = "/DeviceGray";
            else if (Data[1] % 3 == 2)
                colorspace = "/DeviceCMYK";

            uint32_t width = ((Data[2] % 100) + 1) * 4;
            uint32_t height = ((Data[3] % 100) + 1) * 4;

            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/XObject\n"
                               "  /Subtype/Image\n"
                               "  /Width %u\n"
                               "  /Height %u\n"
                               "  /ColorSpace%s\n"
                               "  /BitsPerComponent 8\n"
                               "  /Length %zu\n"
                               ">>\n"
                               "stream\n",
                          img_obj, width, height, colorspace, Size - 4);

            // Write image data
            for (size_t i = 4; i < Size && i < 1004; i++)
            {
                pdfOut_printf(pdf, "%c", Data[i]);
            }

            pdfOut_printf(pdf, "\nendstream\n"
                               "endobj\n");

            // Create content stream
            int content_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length 50\n"
                               ">>\n"
                               "stream\n"
                               "q %u 0 0 %u 100 400 cm /Im1 Do Q\n"
                               "endstream\n"
                               "endobj\n",
                          content_obj, width, height);

            int page_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Page\n"
                               "  /Parent 1 0 R\n"
                               "  /MediaBox [0 0 595 842]\n"
                               "  /Contents %d 0 R\n"
                               "  /Resources << /XObject << /Im1 %d 0 R >> >>\n"
                               ">>\n"
                               "endobj\n",
                          page_obj, content_obj, img_obj);

            pdfOut_add_page(pdf, page_obj);
        }
        else // Vector/PostScript-like processing
        {
            // Create vector graphics content
            int vector_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length 300\n"
                               ">>\n"
                               "stream\n"
                               "q\n"
                               "1 0 0 1 200 400 cm\n"
                               "%d %d %d rg\n" // RGB from data
                               "%d %d %d RG\n" // Stroke RGB from data
                               "2 w\n"
                               "%d %d m\n"        // Move to from data
                               "%d %d l\n"        // Line to from data
                               "%d %d %d %d re\n" // Rectangle from data
                               "B\n"
                               "Q\n"
                               "endstream\n"
                               "endobj\n",
                          vector_obj,
                          Data[1] % 256, Data[2] % 256, Data[3] % 256,                 // Fill color
                          Data[4] % 256, Data[5] % 256, Data[6] % 256,                 // Stroke color
                          Data[7] % 200, Data[0] % 200,                                // Move to
                          (Data[1] + 50) % 200, (Data[2] + 50) % 200,                  // Line to
                          Data[3] % 100, Data[4] % 100, Data[5] % 100, Data[6] % 100); // Rectangle

            int page_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Page\n"
                               "  /Parent 1 0 R\n"
                               "  /MediaBox [0 0 595 842]\n"
                               "  /Contents %d 0 R\n"
                               ">>\n"
                               "endobj\n",
                          page_obj, vector_obj);

            pdfOut_add_page(pdf, page_obj);
        }

        pdfOut_finish_pdf(pdf);
        pdfOut_free(pdf);
    }

    // Cleanup
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

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

    // Create temporary PostScript input file
    char ps_file[] = "/tmp/fuzz_ps_input_XXXXXX";
    int ps_fd = mkstemp(ps_file);
    if (ps_fd < 0)
    {
        return 0;
    }

    // Write PostScript data
    if (write(ps_fd, Data, Size) != (ssize_t)Size)
    {
        close(ps_fd);
        unlink(ps_file);
        return 0;
    }
    close(ps_fd);

    // Test PostScript to PDF conversion
    pdfOut *pdf = pdfOut_new();
    if (pdf)
    {
        pdfOut_begin_pdf(pdf);

        // Check for PostScript header patterns
        if (Size >= 4 && (strncmp((char *)Data, "%!PS", 4) == 0 || strncmp((char *)Data, "%PDF", 4) == 0))
        {
            // Process as PostScript document
            char *ps_content = (char *)malloc(Size + 1);
            if (ps_content)
            {
                memcpy(ps_content, Data, Size);
                ps_content[Size] = '\0';

                // Sanitize PostScript content for PDF embedding
                for (size_t i = 0; i < Size; i++)
                {
                    if (ps_content[i] < 32 && ps_content[i] != '\n' && ps_content[i] != '\r' && ps_content[i] != '\t')
                    {
                        ps_content[i] = ' ';
                    }
                }

                // Create PostScript content stream
                int ps_obj = pdfOut_add_xref(pdf);
                pdfOut_printf(pdf, "%d 0 obj\n"
                                   "<</Length %zu\n"
                                   ">>\n"
                                   "stream\n"
                                   "%s\n"
                                   "endstream\n"
                                   "endobj\n",
                              ps_obj, strlen(ps_content), ps_content);

                // Create page that references PostScript content
                int page_obj = pdfOut_add_xref(pdf);
                pdfOut_printf(pdf, "%d 0 obj\n"
                                   "<</Type/Page\n"
                                   "  /Parent 1 0 R\n"
                                   "  /MediaBox [0 0 595 842]\n"
                                   "  /Contents %d 0 R\n"
                                   ">>\n"
                                   "endobj\n",
                              page_obj, ps_obj);

                pdfOut_add_page(pdf, page_obj);
                free(ps_content);
            }
        }

        // Test PostScript graphics commands
        if (Size >= 20)
        {
            // Create graphics state content
            int gfx_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length 200\n"
                               ">>\n"
                               "stream\n"
                               "q\n"
                               "1 0 0 1 100 700 cm\n"
                               "%d %d %d rg\n" // RGB color from data
                               "100 0 0 100 re\n"
                               "f\n"
                               "Q\n"
                               "endstream\n"
                               "endobj\n",
                          gfx_obj, Data[0] % 256, Data[1] % 256, Data[2] % 256);

            int gfx_page_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Page\n"
                               "  /Parent 1 0 R\n"
                               "  /MediaBox [0 0 595 842]\n"
                               "  /Contents %d 0 R\n"
                               ">>\n"
                               "endobj\n",
                          gfx_page_obj, gfx_obj);

            pdfOut_add_page(pdf, gfx_page_obj);
        }

        // Test PostScript font handling
        if (Size >= 10)
        {
            // Add Type1 font object
            int font_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Font\n"
                               "  /Subtype/Type1\n"
                               "  /BaseFont/Times-Roman\n"
                               ">>\n"
                               "endobj\n",
                          font_obj);

            // Create text content using PostScript-style positioning
            int text_obj = pdfOut_add_xref(pdf);
            char text_sample[32];
            snprintf(text_sample, sizeof(text_sample), "PS Test %02X%02X", Data[5], Data[6]);

            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length 80\n"
                               ">>\n"
                               "stream\n"
                               "BT\n"
                               "/F1 %d Tf\n"
                               "%d %d Td\n"
                               "(%s) Tj\n"
                               "ET\n"
                               "endstream\n"
                               "endobj\n",
                          text_obj,
                          (Data[7] % 20) + 8,   // Font size 8-28
                          (Data[8] % 400) + 50, // X position
                          (Data[9] % 600) + 50, // Y position
                          text_sample);

            int text_page_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Page\n"
                               "  /Parent 1 0 R\n"
                               "  /MediaBox [0 0 595 842]\n"
                               "  /Contents %d 0 R\n"
                               "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                               ">>\n"
                               "endobj\n",
                          text_page_obj, text_obj, font_obj);

            pdfOut_add_page(pdf, text_page_obj);
        }

        pdfOut_finish_pdf(pdf);
        pdfOut_free(pdf);
    }

    // Cleanup
    unlink(ps_file);

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

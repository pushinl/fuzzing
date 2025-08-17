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
    if (Size < 10 || Size > 100000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Create temporary input file for foomatic processing
    char input_file[] = "/tmp/fuzz_foomatic_input_XXXXXX";
    int input_fd = mkstemp(input_file);
    if (input_fd < 0)
    {
        return 0;
    }

    // Write input data
    if (write(input_fd, Data, Size) != (ssize_t)Size)
    {
        close(input_fd);
        unlink(input_file);
        return 0;
    }
    close(input_fd);

    // Test foomatic job processing through PDF generation
    pdfOut *pdf = pdfOut_new();
    if (pdf)
    {
        pdfOut_begin_pdf(pdf);

        // Simulate foomatic job ticket processing
        if (Size >= 20)
        {
            // Extract job parameters from fuzzer data
            uint8_t copies = (Data[0] % 10) + 1; // 1-10 copies
            uint8_t resolution = (Data[1] % 4);  // Resolution index
            uint8_t paper_size = (Data[2] % 3);  // Paper size index
            uint8_t color_mode = (Data[3] % 2);  // Color/BW mode

            const char *resolutions[] = {"300dpi", "600dpi", "1200dpi", "2400dpi"};
            const char *paper_sizes[] = {"A4", "Letter", "Legal"};
            const char *color_modes[] = {"Color", "Monochrome"};

            // Create job info object
            int job_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/Catalog\n"
                               "  /JobTicket << \n"
                               "    /Copies %d\n"
                               "    /Resolution (%s)\n"
                               "    /PageSize (%s)\n"
                               "    /ColorMode (%s)\n"
                               "  >>\n"
                               ">>\n"
                               "endobj\n",
                          job_obj, copies,
                          resolutions[resolution],
                          paper_sizes[paper_size],
                          color_modes[color_mode]);

            // Process different data types based on header
            if (Size >= 4 && strncmp((char *)Data, "%!PS", 4) == 0)
            {
                // PostScript data through foomatic
                char *ps_data = (char *)malloc(Size + 1);
                if (ps_data)
                {
                    memcpy(ps_data, Data, Size);
                    ps_data[Size] = '\0';

                    // Sanitize
                    for (size_t i = 0; i < Size; i++)
                    {
                        if (ps_data[i] < 32 && ps_data[i] != '\n' && ps_data[i] != '\r' && ps_data[i] != '\t')
                        {
                            ps_data[i] = ' ';
                        }
                    }

                    int ps_content_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Length %zu\n"
                                       ">>\n"
                                       "stream\n"
                                       "%% Foomatic processed PostScript\n"
                                       "%s\n"
                                       "endstream\n"
                                       "endobj\n",
                                  ps_content_obj, strlen(ps_data) + 40, ps_data);

                    free(ps_data);
                }
            }
            else if (Size >= 2 && Data[0] == 0xFF && Data[1] == 0xD8)
            {
                // JPEG data through foomatic
                int jpeg_obj = pdfOut_add_xref(pdf);
                pdfOut_printf(pdf, "%d 0 obj\n"
                                   "<</Type/XObject\n"
                                   "  /Subtype/Image\n"
                                   "  /Width 200\n"
                                   "  /Height 200\n"
                                   "  /ColorSpace/DeviceRGB\n"
                                   "  /BitsPerComponent 8\n"
                                   "  /Filter/DCTDecode\n"
                                   "  /Length %zu\n"
                                   ">>\n"
                                   "stream\n",
                              jpeg_obj, Size);

                // Write JPEG data (first 1000 bytes max)
                for (size_t i = 0; i < Size && i < 1000; i++)
                {
                    pdfOut_printf(pdf, "%c", Data[i]);
                }

                pdfOut_printf(pdf, "\nendstream\n"
                                   "endobj\n");
            }
            else
            {
                // Text data through foomatic
                char *text_data = (char *)malloc(Size + 1);
                if (text_data)
                {
                    memcpy(text_data, Data, Size);
                    text_data[Size] = '\0';

                    // Sanitize text
                    for (size_t i = 0; i < Size; i++)
                    {
                        if (text_data[i] < 32 && text_data[i] != '\n' && text_data[i] != '\r' && text_data[i] != '\t')
                        {
                            text_data[i] = ' ';
                        }
                    }

                    // Add font for text rendering
                    int font_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/Font\n"
                                       "  /Subtype/Type1\n"
                                       "  /BaseFont/Courier\n"
                                       ">>\n"
                                       "endobj\n",
                                  font_obj);

                    int text_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Length %zu\n"
                                       ">>\n"
                                       "stream\n"
                                       "BT\n"
                                       "/F1 10 Tf\n"
                                       "50 750 Td\n"
                                       "(%s) Tj\n"
                                       "ET\n"
                                       "endstream\n"
                                       "endobj\n",
                                  text_obj, strlen(text_data) + 50, text_data);

                    // Create page with foomatic processing info
                    int page_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/Page\n"
                                       "  /Parent 1 0 R\n"
                                       "  /MediaBox [0 0 595 842]\n"
                                       "  /Contents %d 0 R\n"
                                       "  /Resources << /Font << /F1 %d 0 R >> >>\n"
                                       ">>\n"
                                       "endobj\n",
                                  page_obj, text_obj, font_obj);

                    pdfOut_add_page(pdf, page_obj);
                    free(text_data);
                }
            }
        }

        // Test foomatic printer-specific commands
        if (Size >= 15)
        {
            // Simulate printer command processing
            uint8_t cmd_type = Data[10] % 5;

            int cmd_obj = pdfOut_add_xref(pdf);
            const char *cmd_names[] = {"PJL", "PCL", "ESC/P", "Canon", "HP"};

            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/ExtGState\n"
                               "  /PrinterCmd (%s)\n"
                               "  /CmdData <%02X%02X%02X%02X>\n"
                               ">>\n"
                               "endobj\n",
                          cmd_obj, cmd_names[cmd_type],
                          Data[11], Data[12], Data[13], Data[14]);
        }

        pdfOut_finish_pdf(pdf);
        pdfOut_free(pdf);
    }

    // Cleanup
    unlink(input_file);

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

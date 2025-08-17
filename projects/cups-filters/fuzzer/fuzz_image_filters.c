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

    // Test different image format patterns
    if (Size >= 4)
    {
        // Test JPEG processing
        if (Data[0] == 0xFF && Data[1] == 0xD8 && Data[2] == 0xFF)
        {
            char jpeg_file[] = "/tmp/fuzz_image_jpeg_XXXXXX";
            int jpeg_fd = mkstemp(jpeg_file);
            if (jpeg_fd >= 0)
            {
                write(jpeg_fd, Data, Size);
                close(jpeg_fd);

                // Create PDF output for image
                pdfOut *pdf = pdfOut_new();
                if (pdf)
                {
                    pdfOut_begin_pdf(pdf);

                    // Add image object placeholder
                    int img_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/XObject\n"
                                       "  /Subtype/Image\n"
                                       "  /Width 100\n"
                                       "  /Height 100\n"
                                       "  /ColorSpace/DeviceRGB\n"
                                       "  /BitsPerComponent 8\n"
                                       "  /Length %zu\n"
                                       ">>\n"
                                       "stream\n",
                                  img_obj, Size);

                    // Write image data
                    for (size_t i = 0; i < Size && i < 1000; i++)
                    {
                        pdfOut_printf(pdf, "%c", Data[i]);
                    }

                    pdfOut_printf(pdf, "\nendstream\n"
                                       "endobj\n");

                    // Add page with image
                    int page_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/Page\n"
                                       "  /Parent 1 0 R\n"
                                       "  /MediaBox [0 0 595 842]\n"
                                       "  /Resources << /XObject << /Im1 %d 0 R >> >>\n"
                                       ">>\n"
                                       "endobj\n",
                                  page_obj, img_obj);

                    pdfOut_add_page(pdf, page_obj);
                    pdfOut_finish_pdf(pdf);
                    pdfOut_free(pdf);
                }

                unlink(jpeg_file);
            }
        }

        // Test PNG processing
        if (Size >= 8 && Data[0] == 0x89 && Data[1] == 0x50 && Data[2] == 0x4E && Data[3] == 0x47)
        {
            char png_file[] = "/tmp/fuzz_image_png_XXXXXX";
            int png_fd = mkstemp(png_file);
            if (png_fd >= 0)
            {
                write(png_fd, Data, Size);
                close(png_fd);

                // Process PNG through PDF conversion
                pdfOut *pdf = pdfOut_new();
                if (pdf)
                {
                    pdfOut_begin_pdf(pdf);

                    int content_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Length 50\n"
                                       ">>\n"
                                       "stream\n"
                                       "q 200 0 0 200 100 600 cm /Im1 Do Q\n"
                                       "endstream\n"
                                       "endobj\n",
                                  content_obj);

                    int page_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/Page\n"
                                       "  /Parent 1 0 R\n"
                                       "  /MediaBox [0 0 595 842]\n"
                                       "  /Contents %d 0 R\n"
                                       ">>\n"
                                       "endobj\n",
                                  page_obj, content_obj);

                    pdfOut_add_page(pdf, page_obj);
                    pdfOut_finish_pdf(pdf);
                    pdfOut_free(pdf);
                }

                unlink(png_file);
            }
        }

        // Test TIFF processing
        if ((Data[0] == 0x49 && Data[1] == 0x49) || (Data[0] == 0x4D && Data[1] == 0x4D))
        {
            char tiff_file[] = "/tmp/fuzz_image_tiff_XXXXXX";
            int tiff_fd = mkstemp(tiff_file);
            if (tiff_fd >= 0)
            {
                write(tiff_fd, Data, Size);
                close(tiff_fd);

                // Basic TIFF to PDF processing
                pdfOut *pdf = pdfOut_new();
                if (pdf)
                {
                    pdfOut_begin_pdf(pdf);

                    int page_obj = pdfOut_add_xref(pdf);
                    pdfOut_printf(pdf, "%d 0 obj\n"
                                       "<</Type/Page\n"
                                       "  /Parent 1 0 R\n"
                                       "  /MediaBox [0 0 595 842]\n"
                                       ">>\n"
                                       "endobj\n",
                                  page_obj);

                    pdfOut_add_page(pdf, page_obj);
                    pdfOut_finish_pdf(pdf);
                    pdfOut_free(pdf);
                }

                unlink(tiff_file);
            }
        }
    }

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

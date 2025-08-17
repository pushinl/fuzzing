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

    // Create temporary raster input file
    char raster_file[] = "/tmp/fuzz_raster_input_XXXXXX";
    int raster_fd = mkstemp(raster_file);
    if (raster_fd < 0)
    {
        return 0;
    }

    // Write raster data
    if (write(raster_fd, Data, Size) != (ssize_t)Size)
    {
        close(raster_fd);
        unlink(raster_file);
        return 0;
    }
    close(raster_fd);

    // Test raster to PDF conversion
    pdfOut *pdf = pdfOut_new();
    if (pdf)
    {
        pdfOut_begin_pdf(pdf);

        // Simulate raster header processing
        if (Size >= 32)
        {
            // Extract basic raster parameters from fuzzer data
            uint32_t width = ((uint32_t)Data[0] << 24) | ((uint32_t)Data[1] << 16) |
                             ((uint32_t)Data[2] << 8) | Data[3];
            uint32_t height = ((uint32_t)Data[4] << 24) | ((uint32_t)Data[5] << 16) |
                              ((uint32_t)Data[6] << 8) | Data[7];

            // Clamp dimensions to reasonable values
            width = (width % 1000) + 1;
            height = (height % 1000) + 1;

            // Create raster image object
            int img_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/XObject\n"
                               "  /Subtype/Image\n"
                               "  /Width %u\n"
                               "  /Height %u\n"
                               "  /ColorSpace/DeviceRGB\n"
                               "  /BitsPerComponent 8\n"
                               "  /Length %zu\n"
                               ">>\n"
                               "stream\n",
                          img_obj, width, height, Size - 32);

            // Write raster pixel data (skip header simulation)
            size_t pixel_start = 32;
            for (size_t i = pixel_start; i < Size && i < pixel_start + 2000; i++)
            {
                pdfOut_printf(pdf, "%c", Data[i]);
            }

            pdfOut_printf(pdf, "\nendstream\n"
                               "endobj\n");

            // Create content stream that uses the raster image
            int content_obj = pdfOut_add_xref(pdf);
            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Length 40\n"
                               ">>\n"
                               "stream\n"
                               "q %u 0 0 %u 50 400 cm /Im1 Do Q\n"
                               "endstream\n"
                               "endobj\n",
                          content_obj, width, height);

            // Create page
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

        // Test different raster color modes
        if (Size >= 16)
        {
            uint8_t color_mode = Data[8] % 4; // 0=RGB, 1=CMYK, 2=Gray, 3=Bitmap

            int mode_obj = pdfOut_add_xref(pdf);
            const char *colorspace;
            switch (color_mode)
            {
            case 0:
                colorspace = "/DeviceRGB";
                break;
            case 1:
                colorspace = "/DeviceCMYK";
                break;
            case 2:
                colorspace = "/DeviceGray";
                break;
            default:
                colorspace = "/DeviceGray";
                break;
            }

            pdfOut_printf(pdf, "%d 0 obj\n"
                               "<</Type/XObject\n"
                               "  /Subtype/Image\n"
                               "  /Width 10\n"
                               "  /Height 10\n"
                               "  /ColorSpace%s\n"
                               "  /BitsPerComponent 8\n"
                               "  /Length %zu\n"
                               ">>\n"
                               "stream\n",
                          mode_obj, colorspace, Size - 16);

            // Write color mode specific data
            for (size_t i = 16; i < Size && i < 116; i++)
            {
                pdfOut_printf(pdf, "%c", Data[i]);
            }

            pdfOut_printf(pdf, "\nendstream\n"
                               "endobj\n");
        }

        pdfOut_finish_pdf(pdf);
        pdfOut_free(pdf);
    }

    // Cleanup
    unlink(raster_file);

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

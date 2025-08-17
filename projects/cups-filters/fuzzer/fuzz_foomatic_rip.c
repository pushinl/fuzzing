#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

// Include foomatic-rip headers
#include "foomaticrip.h"
#include "util.h"
#include "options.h"
#include "pdf.h"
#include "postscript.h"
#include "process.h"
#include "spooler.h"
#include "renderer.h"

static void redirect_stdout_stderr(); // hide stdout

// Test foomatic-rip utility functions
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 5 || Size > 50000)
    {
        return 0;
    }

    redirect_stdout_stderr();

    // Test various foomatic-rip utility functions with fuzzer input

    // Create null-terminated string from fuzz data
    char *buf = (char *)malloc(Size + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Test string utility functions
    char *trimmed = strtrim(buf);
    if (trimmed)
    {
        // Test if string is empty
        int empty = isempty(trimmed);
        (void)empty;

        // Test whitespace skipping
        const char *skipped = skip_whitespace(trimmed);
        (void)skipped;

        // Test line counting
        int lines = line_count(trimmed);
        (void)lines;

        free(trimmed);
    }

    // Test dynamic string operations
    dstr_t *dstr = create_dstr();
    if (dstr)
    {
        dstr_append(dstr, buf, Size);
        dstr_append_printf(dstr, " appended %zu bytes", Size);

        // Test dstring operations
        if (dstr->data)
        {
            char *copy = strdup(dstr->data);
            if (copy)
            {
                free(copy);
            }
        }

        free_dstr(dstr);
    }

    // Test option parsing functions with fuzz data
    if (Size > 10)
    {
        // Test option string parsing (safely)
        char *option_copy = strndup(buf, Size < 1000 ? Size : 1000);
        if (option_copy)
        {
            // Parse as if it's an option string
            option_t *opt = find_option(option_copy);
            if (opt)
            {
                // Test option value extraction
                const char *value = option_get_value(opt, "test");
                (void)value;
            }
            free(option_copy);
        }
    }

    // Test PDF detection and parsing
    if (Size > 4)
    {
        // Check if data looks like PDF
        int is_pdf = is_pdf_file(buf, Size);
        (void)is_pdf;

        if (is_pdf)
        {
            // Try basic PDF parsing
            pdf_t *pdf = pdf_parse_header(buf, Size);
            if (pdf)
            {
                // Test PDF operations
                int pages = pdf_get_page_count(pdf);
                (void)pages;
                pdf_free(pdf);
            }
        }
    }

    // Test PostScript detection and parsing
    if (Size > 2)
    {
        int is_ps = is_postscript_file(buf, Size);
        (void)is_ps;

        if (is_ps)
        {
            // Try basic PostScript parsing
            ps_t *ps = ps_parse_header(buf, Size);
            if (ps)
            {
                // Test PostScript operations
                int pages = ps_get_page_count(ps);
                (void)pages;
                ps_free(ps);
            }
        }
    }

    // Test command processing functions
    if (Size > 5 && Size < 500)
    {
        char *cmd_copy = strndup(buf, Size);
        if (cmd_copy)
        {
            // Test command parsing
            list_t *args = parse_command_line(cmd_copy);
            if (args)
            {
                // Test argument processing
                int argc = list_length(args);
                (void)argc;
                list_free(args, free);
            }
            free(cmd_copy);
        }
    }

    free(buf);
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

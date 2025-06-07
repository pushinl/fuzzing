/*
 * PPD, Cache and PWG fuzz program for CUPS
 *
 * This harness is a combination of
 * testppd.c, testcache.c and testpwg.c
 *
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include "ppd-private.h"
#include "file-private.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int fuzz_ppd(char *string, int len, char *filename, char *pwgname);
void unlink_tempfile(void);

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  /*
   * We need a huge input, because it should contain
   * options and ppd file
   */
  if (Size < 1000)
    return 1;

  atexit(unlink_tempfile);

  char *filename = (char *)malloc(sizeof(char) * 256);
  char *pwgname = (char *)malloc(sizeof(char) * 256);
  sprintf(filename, "/tmp/fuzz_ppd.%d.ppd", getpid());
  sprintf(pwgname, "/tmp/fuzz_ppd.%d.pwg", getpid());

  char *string = (char *)calloc(sizeof(char), Size + 1);
  memcpy(string, Data, Size);
  int len = Size;

  fuzz_ppd(string, len, filename, pwgname);

  unlink_tempfile();
  free(filename);
  free(pwgname);
  free(string);
  return 0;
}

int fuzz_ppd(char *data, int len, char *filename, char *pwgname)
{
  int num_options = 0, // number of fuzz-generated options
      finishings[1024],
      width,
      length;
  cups_option_t *options = NULL;
  _ppd_cache_t *pc,
      *pc2;
  ppd_choice_t *ppd_bin;
  ppd_attr_t *attr;
  ppd_size_t minsize,
      maxsize,
      *size;
  cups_page_header2_t header;
  ipp_t *job;
  char *ppdsize = NULL;
  char *legacy = NULL;
  char *pwg = NULL;
  char *ppdmedia = NULL;
  char *marked_option = NULL;
  char *options_str = NULL;
  char **cups_options = NULL;
  char **cups_values = NULL;
  ppd_file_t *ppd = NULL;
  char *choice = NULL;
  int elem_counter = 0;
  FILE *fp = NULL;
  char *pagesize = NULL;

  /*
   * Create and fill variables (options)
   * with fuzz-generated values
   */

  ppdsize = strdup(data);
  if (!ppdsize)
  {
    return 1;
  }
  len -= strlen(ppdsize) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    return 1;
  }
  data += strlen(ppdsize) + 1;

  legacy = strdup(data);
  if (!legacy)
  {
    free(ppdsize);
    return 1;
  }
  len -= strlen(legacy) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    free(legacy);
    return 1;
  }
  data += strlen(legacy) + 1;

  pwg = strdup(data);
  if (!pwg)
  {
    free(ppdsize);
    free(legacy);
    return 1;
  }
  len -= strlen(pwg) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    return 1;
  }
  data += strlen(pwg) + 1;

  ppdmedia = strdup(data);
  if (!ppdmedia)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    return 1;
  }
  len -= strlen(ppdmedia) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    return 1;
  }
  data += strlen(ppdmedia) + 1;

  marked_option = strdup(data);
  if (!marked_option)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    return 1;
  }
  len -= strlen(marked_option) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    return 1;
  }
  data += strlen(marked_option) + 1;

  options_str = strdup(data);
  if (!options_str)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    return 1;
  }
  len -= strlen(options_str) + 1;
  if (len <= 0)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }
  data += strlen(options_str) + 1;

  char buf[12] = {0};
  if (!strncpy(buf, data, 11))
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  length = atoi(buf);
  data += strlen(buf);
  len -= strlen(buf);

  if (!strncpy(buf, data, 11))
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  width = atoi(buf);
  data += strlen(buf);
  len -= strlen(buf);

  /*
   * Create and fill the array of cups options
   * and values to check correct work of
   * ppdMarkOption(), cupsGetOption(),
   * cupsGetConflicts(), cupsResolveConflicts()
   * and ppdInstallableConflict() functions
   */

  cups_options = (char **)malloc(sizeof(char *) * 2);
  if (!cups_options)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  cups_values = (char **)malloc(sizeof(char *) * 2);
  if (!cups_values)
  {
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    free(cups_options);
    return 1;
  }

  for (int i = 0; i < strlen(options_str); i++)
  {
    cups_options[elem_counter] = (char *)malloc(sizeof(char));
    if (!cups_options[elem_counter])
    {
      for (int j = 0; j < elem_counter; j++)
      {
        free(cups_options[j]);
        free(cups_values[j]);
      }
      free(cups_options);
      free(cups_values);
      free(ppdsize);
      free(legacy);
      free(pwg);
      free(ppdmedia);
      free(marked_option);
      free(options_str);
      return 1;
    }

    cups_values[elem_counter] = (char *)malloc(sizeof(char));
    if (!cups_values[elem_counter])
    {
      free(cups_options[elem_counter]);
      for (int j = 0; j < elem_counter; j++)
      {
        free(cups_options[j]);
        free(cups_values[j]);
      }
      free(cups_options);
      free(cups_values);
      free(ppdsize);
      free(legacy);
      free(pwg);
      free(ppdmedia);
      free(marked_option);
      free(options_str);
      return 1;
    }

    cups_options[elem_counter][0] = '\0';
    cups_values[elem_counter][0] = '\0';
    if (!options_str[i])
      break;

    int counter = 0;
    while (options_str[i] != '=' && options_str[i] && options_str[i] != ' ')
    {
      cups_options[elem_counter] = (char *)realloc(cups_options[elem_counter], sizeof(char) * (counter + 2));
      if (!cups_options[elem_counter])
      {
        for (int j = 0; j < elem_counter; j++)
        {
          free(cups_options[j]);
          free(cups_values[j]);
        }
        free(cups_values[elem_counter]);
        free(cups_options);
        free(cups_values);
        free(ppdsize);
        free(legacy);
        free(pwg);
        free(ppdmedia);
        free(marked_option);
        free(options_str);
        return 1;
      }

      cups_options[elem_counter][counter] = options_str[i];
      counter++;
      i++;
    }
    cups_options[elem_counter][counter] = '\0';
    if (options_str[i] == '=')
    {
      ++i;
      counter = 0;
      while (options_str[i] != ' ' && options_str[i])
      {
        cups_values[elem_counter] = (char *)realloc(cups_values[elem_counter], sizeof(char) * (counter + 2));
        if (!cups_values[elem_counter])
        {
          for (int j = 0; j < elem_counter; j++)
          {
            free(cups_options[j]);
            free(cups_values[j]);
          }
          free(cups_options[elem_counter]);
          free(cups_options);
          free(cups_values);
          free(ppdsize);
          free(legacy);
          free(pwg);
          free(ppdmedia);
          free(marked_option);
          free(options_str);
          return 1;
        }

        cups_values[elem_counter][counter] = options_str[i];
        counter++;
        i++;
      }
      cups_values[elem_counter][counter] = '\0';
    }
    elem_counter++;
    cups_options = (char **)realloc(cups_options, sizeof(char *) * (elem_counter + 1));
    if (!cups_options)
    {
      for (int j = 0; j < elem_counter; j++)
      {
        free(cups_values[j]);
      }
      free(cups_values);
      free(ppdsize);
      free(legacy);
      free(pwg);
      free(ppdmedia);
      free(marked_option);
      free(options_str);
      return 1;
    }

    cups_values = (char **)realloc(cups_values, sizeof(char *) * (elem_counter + 1));
    if (!cups_values)
    {
      for (int j = 0; j < elem_counter - 1; j++)
      {
        free(cups_options[j]);
      }
      free(cups_options);
      free(ppdsize);
      free(legacy);
      free(pwg);
      free(ppdmedia);
      free(marked_option);
      free(options_str);
      return 1;
    }
  }
  if (len <= 0)
  {
    for (int i = 0; i < elem_counter; i++)
    {
      free(cups_options[i]);
      free(cups_values[i]);
    }
    free(cups_options);
    free(cups_values);
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  /*
   * Create and fill .ppd file
   * with fuzz-generated data
   */

  fp = fopen(filename, "wb");
  if (!fp)
  {
    for (int i = 0; i < elem_counter; i++)
    {
      free(cups_options[i]);
      free(cups_values[i]);
    }
    free(cups_options);
    free(cups_values);
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  fwrite(data, sizeof(*data), len, fp);
  fclose(fp);
  fp = NULL;

  if ((ppd = ppdOpenFile(filename)) == NULL)
  {
    ppd_status_t err; /* Last error in file */
    int line;         /* Line number in file */
    ppdLastError(&line);
    ppdErrorString(err);
    for (int i = 0; i < elem_counter; i++)
    {
      free(cups_options[i]);
      free(cups_values[i]);
    }
    free(cups_options);
    free(cups_values);
    free(ppdsize);
    free(legacy);
    free(pwg);
    free(ppdmedia);
    free(marked_option);
    free(options_str);
    return 1;
  }

  pc = _ppdCacheCreateWithPPD(NULL, ppd);

  /*
   * Do pwg tests from testpwg.c
   */

  _ppdCacheWriteFile(pc, pwgname, NULL);
  pc2 = _ppdCacheCreateWithFile(pwgname, NULL);
  _ppdCacheDestroy(pc2);
  ppdPageSize(ppd, ppdsize);
  pagesize = _ppdCacheGetPageSize(pc, NULL, ppdsize, NULL);
  job = ippNew();
  ippDelete(job);
  pwgMediaForPWG(pwg);
  pwgMediaForLegacy(legacy);
  pwgMediaForPPD(ppdmedia);
  pwgMediaForSize(width, length);

  num_options = cupsParseOptions(options_str, num_options, &options);
  ppdMarkDefaults(ppd);
  cupsMarkOptions(ppd, num_options, options);
  ppdConflicts(ppd);

  _ppdCacheGetFinishingValues(ppd, pc, (int)sizeof(finishings) / sizeof(finishings[0]), finishings);
  cupsRasterInterpretPPD(&header, ppd, num_options, options, NULL);

  if (strlen(marked_option) > 0)
  {
    choice = (char *)calloc(1, sizeof(char));
    if (!choice)
    {
      cupsFreeOptions(num_options, options);
      _ppdCacheDestroy(pc);
      ppdClose(ppd);
      for (int i = 0; i < elem_counter; i++)
      {
        free(cups_options[i]);
        free(cups_values[i]);
      }
      free(cups_options);
      free(cups_values);
      free(ppdsize);
      free(legacy);
      free(pwg);
      free(ppdmedia);
      free(marked_option);
      free(options_str);
      return 1;
    }

    for (int i = 0; i < strlen(marked_option); i++)
    {
      if (!marked_option[i] || marked_option[i] != ' ')
      {
        choice = (char *)realloc(choice, sizeof(char) * (i + 2));
        if (!choice)
        {
          cupsFreeOptions(num_options, options);
          _ppdCacheDestroy(pc);
          ppdClose(ppd);
          for (int i = 0; i < elem_counter; i++)
          {
            free(cups_options[i]);
            free(cups_values[i]);
          }
          free(cups_options);
          free(cups_values);
          free(ppdsize);
          free(legacy);
          free(pwg);
          free(ppdmedia);
          free(marked_option);
          free(options_str);
          return 1;
        }
        choice[i] = marked_option[i];
        choice[i + 1] = '\0';
      }
      else
        break;
    }
    ppdFindAttr(ppd, choice, marked_option + strlen(choice));
    ppdFindNextAttr(ppd, choice, NULL);
    if ((ppd_bin = ppdFindMarkedChoice(ppd, choice)) != NULL)
      _ppdCacheGetBin(pc, ppd_bin->choice);
    char buffer[1024] = {0};
    ppdLocalizeIPPReason(ppd, choice, marked_option + strlen(choice), buffer, sizeof(buffer));
    for (int i = 0; i < elem_counter; i++)
    {
      ppdMarkOption(ppd, cups_options[i], cups_values[i]);
      cupsGetOption(cups_options[i], num_options, options);

      cups_option_t *temp_options = options;
      int temp_num_options = num_options;

      num_options = cupsGetConflicts(ppd, cups_options[i], cups_values[i], &options);

      if (temp_options != options && temp_num_options > 0)
      {
        cupsFreeOptions(temp_num_options, temp_options);
      }

      temp_options = options;
      temp_num_options = num_options;

      int res = cupsResolveConflicts(ppd, cups_options[i], cups_values[i], &num_options, &options);

      if (res && temp_options != options && temp_num_options > 0)
      {
        cupsFreeOptions(temp_num_options, temp_options);
      }

      ppdInstallableConflict(ppd, cups_options[i], cups_values[i]);
    }
    ppdInstallableConflict(ppd, options_str, choice);
    ppdLocalizeMarkerName(ppd, choice);
    free(choice);
    choice = NULL;
  }

  for (int i = 0; i < 5; i++)
    ppdEmitString(ppd, i, 0.0);

  ppdPageSizeLimits(ppd, &minsize, &maxsize);
  ppdPageSize(ppd, NULL);

  for (int i = 0; i < elem_counter; i++)
  {
    free(cups_options[i]);
    free(cups_values[i]);
  }

  free(cups_options);
  free(cups_values);

  cupsFreeOptions(num_options, options);
  _ppdCacheDestroy(pc);
  ppdClose(ppd);

  free(options_str);
  free(ppdsize);
  free(marked_option);
  free(legacy);
  free(pwg);
  free(ppdmedia);

  if (pagesize)
    free(pagesize);

  return 0;
}

void unlink_tempfile(void)
{
  char filename[256];
  sprintf(filename, "/tmp/fuzz_ppd.%d.ppd", getpid());
  unlink(filename);
  sprintf(filename, "/tmp/fuzz_ppd.%d.pwg", getpid());
  unlink(filename);
  sprintf(filename, "%s.N", filename);
  unlink(filename);
}

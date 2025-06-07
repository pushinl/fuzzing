#include "ppd-private.h"
#include "file-private.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static void unlink_tempfile(void);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1000)
    return 1;

  char *filename = NULL, *pwgname = NULL, *string = NULL;
  int result = 0;

  atexit(unlink_tempfile);

  filename = (char *)malloc(256);
  pwgname = (char *)malloc(256);
  if (!filename || !pwgname)
    goto cleanup;

  snprintf(filename, 256, "/tmp/fuzz_ppd.%d.ppd", getpid());
  snprintf(pwgname, 256, "/tmp/fuzz_ppd.%d.pwg", getpid());

  string = (char *)calloc(1, Size + 1);
  if (!string)
    goto cleanup;
  memcpy(string, Data, Size);

  result = fuzz_ppd(string, Size, filename, pwgname);

cleanup:
  free(filename);
  free(pwgname);
  free(string);
  return result;
}

int fuzz_ppd(char *data, int len, char *filename, char *pwgname) {
  int result = 1;

  char *ppdsize = NULL, *legacy = NULL, *pwg = NULL, *ppdmedia = NULL;
  char *marked_option = NULL, *options_str = NULL;
  char **cups_options = NULL, **cups_values = NULL;
  int elem_counter = 0;
  cups_option_t *options = NULL;
  _ppd_cache_t *pc = NULL, *pc2 = NULL;
  ppd_file_t *ppd = NULL;
  cups_page_header2_t header;
  ipp_t *job = NULL;

  // Parse strings from data
  #define PARSE_STR(var)                             \
    do {                                             \
      var = strdup(data);                            \
      if (!var) goto cleanup;                        \
      int l = strlen(var) + 1;                       \
      if ((len -= l) <= 0) goto cleanup;             \
      data += l;                                     \
    } while (0)

  PARSE_STR(ppdsize);
  PARSE_STR(legacy);
  PARSE_STR(pwg);
  PARSE_STR(ppdmedia);
  PARSE_STR(marked_option);
  PARSE_STR(options_str);

  // Parse width/length
  int width = 0, length = 0;
  char buf[12] = {0};
  if (!strncpy(buf, data, 11)) goto cleanup;
  length = atoi(buf);
  data += strlen(buf);
  len -= strlen(buf);
  if (!strncpy(buf, data, 11)) goto cleanup;
  width = atoi(buf);
  data += strlen(buf);
  len -= strlen(buf);

  // Parse cups options
  cups_options = (char **)malloc(sizeof(char *) * 2);
  cups_values = (char **)malloc(sizeof(char *) * 2);
  if (!cups_options || !cups_values) goto cleanup;

  int i = 0, counter = 0;
  while (i < strlen(options_str)) {
    cups_options[elem_counter] = calloc(1, 1);
    cups_values[elem_counter] = calloc(1, 1);
    if (!cups_options[elem_counter] || !cups_values[elem_counter]) goto cleanup;

    counter = 0;
    while (options_str[i] && options_str[i] != '=' && options_str[i] != ' ') {
      cups_options[elem_counter] = realloc(cups_options[elem_counter], counter + 2);
      cups_options[elem_counter][counter++] = options_str[i++];
    }
    cups_options[elem_counter][counter] = '\0';

    if (options_str[i] == '=')
      ++i;

    counter = 0;
    while (options_str[i] && options_str[i] != ' ') {
      cups_values[elem_counter] = realloc(cups_values[elem_counter], counter + 2);
      cups_values[elem_counter][counter++] = options_str[i++];
    }
    cups_values[elem_counter][counter] = '\0';

    while (options_str[i] == ' ') ++i;
    elem_counter++;

    cups_options = realloc(cups_options, sizeof(char *) * (elem_counter + 1));
    cups_values = realloc(cups_values, sizeof(char *) * (elem_counter + 1));
    if (!cups_options || !cups_values) goto cleanup;
  }

  // Write .ppd file
  FILE *fp = fopen(filename, "wb");
  if (!fp) goto cleanup;
  fwrite(data, 1, len, fp);
  fclose(fp);

  if ((ppd = ppdOpenFile(filename)) == NULL) goto cleanup;

  pc = _ppdCacheCreateWithPPD(NULL, ppd);
  _ppdCacheWriteFile(pc, pwgname, NULL);
  pc2 = _ppdCacheCreateWithFile(pwgname, NULL);
  _ppdCacheDestroy(pc2);

  ppdPageSize(ppd, ppdsize);
  _ppdCacheGetPageSize(pc, NULL, ppdsize, NULL);
  job = ippNew();
  ippDelete(job);
  pwgMediaForPWG(pwg);
  pwgMediaForLegacy(legacy);
  pwgMediaForPPD(ppdmedia);
  pwgMediaForSize(width, length);

  int num_options = cupsParseOptions(options_str, 0, &options);
  ppdMarkDefaults(ppd);
  cupsMarkOptions(ppd, num_options, options);
  ppdConflicts(ppd);

  int finishings[1024];
  _ppdCacheGetFinishingValues(ppd, pc, 1024, finishings);
  cupsRasterInterpretPPD(&header, ppd, num_options, options, NULL);

  if (strlen(marked_option)) {
    char *choice = strndup(marked_option, strcspn(marked_option, " "));
    if (choice) {
      ppdFindAttr(ppd, choice, marked_option + strlen(choice));
      ppdFindNextAttr(ppd, choice, NULL);
      ppd_choice_t *ppd_bin = ppdFindMarkedChoice(ppd, choice);
      if (ppd_bin)
        _ppdCacheGetBin(pc, ppd_bin->choice);
      char buffer[1024];
      ppdLocalizeIPPReason(ppd, choice, marked_option + strlen(choice), buffer, sizeof(buffer));
      for (int i = 0; i < elem_counter; i++) {
        ppdMarkOption(ppd, cups_options[i], cups_values[i]);
        cupsGetOption(cups_options[i], num_options, options);
        cupsGetConflicts(ppd, cups_options[i], cups_values[i], &options);
        cupsResolveConflicts(ppd, cups_options[i], cups_values[i], &num_options, &options);
        ppdInstallableConflict(ppd, cups_options[i], cups_values[i]);
      }
      ppdInstallableConflict(ppd, options_str, choice);
      ppdLocalizeMarkerName(ppd, choice);
      free(choice);
    }
  }

  for (int i = 0; i < 5; i++)
    ppdEmitString(ppd, i, 0.0);

  ppd_size_t minsize, maxsize;
  ppdPageSizeLimits(ppd, &minsize, &maxsize);
  ppdPageSize(ppd, NULL);

  result = 0;

cleanup:
  if (pc) _ppdCacheDestroy(pc);
  if (ppd) ppdClose(ppd);
  if (options) cupsFreeOptions(elem_counter, options);

  if (cups_options && cups_values) {
    for (int i = 0; i < elem_counter; i++) {
      free(cups_options[i]);
      free(cups_values[i]);
    }
    free(cups_options);
    free(cups_values);
  }

  free(ppdsize);
  free(legacy);
  free(pwg);
  free(ppdmedia);
  free(marked_option);
  free(options_str);
  return result;
}

void unlink_tempfile(void) {
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd.%d.ppd", getpid());
  unlink(filename);
  snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd.%d.pwg", getpid());
  unlink(filename);
  snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd.%d.pwg.N", getpid());
  unlink(filename);
}
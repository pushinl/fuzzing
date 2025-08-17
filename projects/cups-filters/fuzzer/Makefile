FUZZ_SRCS := $(wildcard fuzz_*.c)
TARGETS := $(basename $(FUZZ_SRCS))

# CC=clang
# CXX=clang++

# ifeq ($(FUZZING_ENGINE), afl)
#     ifneq ($(SANITIZER), memory)
#         export CC=afl-clang-fast
#         export CXX=afl-clang-fast++
#     endif
# endif

# Include paths for cups-filters headers
INCDIR=-I../filter -I../filter/foomatic-rip -I../cupsfilters -I/usr/include/cups -I/usr/include/ppd
LIBDIR=-L../cupsfilters/.libs -L../ppd/.libs -L/usr/lib/x86_64-linux-gnu

BUILD_FLAGS=-g -O0 -D_GNU_SOURCE
# Link against required libraries
LINK_FLAGS=-lcupsfilters -lppd -lcups -lz -ljpeg -ltiff -lpng -lfontconfig -lfreetype -lm -lpthread
# LIB_FUZZING_ENGINE = -fsanitize=fuzzer,address

All: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pdfutils.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -o pdfutils.o ../filter/pdfutils.c

# Build additional object files for foomatic-rip
foomatic_objs:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o util.o ../filter/foomatic-rip/util.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o options.o ../filter/foomatic-rip/options.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o pdf.o ../filter/foomatic-rip/pdf.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o postscript.o ../filter/foomatic-rip/postscript.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o process.o ../filter/foomatic-rip/process.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o spooler.o ../filter/foomatic-rip/spooler.c
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o renderer.o ../filter/foomatic-rip/renderer.c

# Standard harnesses that only need pdfutils.o
fuzz_pdf fuzz_text_filters fuzz_image_filters fuzz_raster_filters fuzz_postscript_filters fuzz_universal_filter: pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o $@.o $@.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o $@ $@.o pdfutils.o $(LINK_FLAGS)

# Foomatic-rip harness needs additional object files
fuzz_foomatic_rip: pdfutils.o foomatic_objs
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o $@.o $@.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o $@ $@.o pdfutils.o util.o options.o pdf.o postscript.o process.o spooler.o renderer.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)
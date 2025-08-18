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

INCDIR=-I./../filter -I./../fontembed -I./../ -I./../cupsfilters
LIBDIR=-L./../filter -L./../fontembed -L./../ -L./../.libs -L./../cupsfilters/.libs

BUILD_FLAGS=-g -O0 
LINK_FLAGS=-g -O0 \
  -lcupsfilters -lcups -lfontconfig -lfreetype -lz -ltiff -lzstd -lwebp -ldeflate \
  -ljpeg -llzma -ljbig -lLerc -lpng -lsharpyuv -lexif \
  -lgnutls -ltasn1 -lhogweed -lgmp -lnettle -lidn2 -lunistring \
  -lavahi-client -lavahi-common -ldbus-1 -lcap -lglib-2.0 -lexpat \
  -lqpdf -lbrotlidec -lbrotlicommon -lpoppler-cpp -lpoppler \
  -lp11-kit -lgssapi_krb5 -llcms2 -lsystemd -lpthread \
  -Wl,--allow-multiple-definition


# LIB_FUZZING_ENGINE = -fsanitize=fuzzer,address

All: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pdfutils.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -o pdfutils.o ../filter/pdfutils.c

$(TARGETS): pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o $@.o $@.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o $@ $@.o pdfutils.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)

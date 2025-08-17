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
LINK_FLAGS=-g -O0 -l:libppd.a -l:libcupsfilters.a -l:libcups.a -l:libfontconfig.a -l:libfreetype.a -l:libbz2.a -lz -l:libtiff.a -l:libzstd.a -l:libwebp.a -l:libdeflate.a \
	-l:libjpeg.a -l:liblzma.a -l:libjbig.a -l:libLerc.a -l:libpng.a -l:libsharpyuv.a -l:libexif.a -l:libgnutls.a -l:libtasn1.a -l:libhogweed.a -l:libgmp.a -l:libnettle.a \
	-l:libidn2.a -l:libunistring.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -l:libcap.a -l:libglib-2.0.a -l:libexpat.a \
	-l:libqpdf.a -l:libbrotlidec.a -l:libbrotlicommon.a -l:libpoppler-cpp.a -l:libpoppler.a\
	-l:libp11-kit.so -l:libgssapi_krb5.so.2 -l:liblcms2.so -lsystemd -lpthread\
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

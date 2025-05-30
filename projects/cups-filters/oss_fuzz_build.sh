#!/bin/bash -eu

# Set fPIE
# export CFLAGS="$CFLAGS -fPIE"
# export CXXFLAGS="$CFLAGS -fPIE"
# export LDFLAGS="$CFLAGS -fPIE"

export CC=clang
export CXX=clang++

export CFLAGS="-fPIE"
export CXXFLAGS="-fPIE"
export LDFLAGS="-fPIE"

export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
export LDFLAGS="-fsanitize=$SANITIZER"

# For regular sanitizers
if [[ $SANITIZER == "coverage" ]]; then
    export CFLAGS=""
    export CXXFLAGS=""
    export LDFLAGS=""
elif [[ $SANITIZER == "undefined" ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize=function"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=function"
    export LDFLAGS="-fno-sanitize=function"
fi

# For fuzz introspector
if [[ $SANITIZER == "introspector" ]]; then
    export CFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export CXXFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export LDFLAGS="-flto"
fi

# for libtool usage
export PATH=$PATH:$SRC/cups-filters
cp $SRC/fuzzing/projects/cups-filters/fuzzer/patch_qpdf_xobject $SRC/cups-filters/filter/pdftopdf/

# Prepare fuzz dir
pushd $SRC/fuzzing/projects/cups-filters/
# Show fuzzer version
echo "OpenPrinting/fuzzing version: $(git rev-parse HEAD)"
cp -r $SRC/fuzzing/projects/cups-filters/fuzzer/. $SRC/cups-filters/ossfuzz/
popd

# Build cups-filters
pushd $SRC/cups-filters

# Show build version
echo "cups-filters version: $(git rev-parse HEAD)"

# For multiple definition of `_cups_isalpha', `_cups_islower`, `_cups_toupper`
export LDFLAGS="$LDFLAGS -Wl,--allow-multiple-definition" # rather important without this, the build will fail

### Temperal fix bug due to libqpdf-dev 9
pushd $SRC/cups-filters/filter/pdftopdf/
patch < patch_qpdf_xobject
popd

./autogen.sh
./configure --enable-static --disable-shared
make # -j$(nproc)
popd

pushd $SRC/cups-filters/ossfuzz/
# Build fuzzers
make
make ossfuzz
popd

# Prepare corpus
pushd $SRC/fuzzing/projects/cups-filters/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
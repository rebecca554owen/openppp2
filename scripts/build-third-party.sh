#!/usr/bin/env bash
# Builds the third-party dependency tree the root project links against:
# Boost, OpenSSL and jemalloc under third-party/.
#
# The root project links the static archives by file name (libssl.a,
# libboost_context.a, ...), so the tree has to exist before it can be
# configured. The CI caches the directory, so this script only runs on a
# cache miss; the versions come from the environment, which keeps the
# workflow the single place that pins them.
#
# Usage:
#   BOOST_VERSION=1.92.0 OPENSSL_VERSION=4.1.0 JEMALLOC_VERSION=5.4.0 \
#   THIRD_PARTY_LIBRARY_DIR="$PWD/third-party" bash scripts/build-third-party.sh
set -euo pipefail

  # Recorded only: this workflow builds against the prebuilt third-party
  # environment it clones, so the versions below are not fetched here.
BOOST_VERSION=${BOOST_VERSION:-1.92.0}
OPENSSL_VERSION=${OPENSSL_VERSION:-4.1.0}
JEMALLOC_VERSION=${JEMALLOC_VERSION:-5.4.0}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
THIRD_PARTY=${THIRD_PARTY_LIBRARY_DIR:-"$ROOT/third-party"}
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

mkdir -p "$THIRD_PARTY"

if [ ! -d "$THIRD_PARTY/boost" ]; then
    echo "=== building Boost $BOOST_VERSION ==="
    cd "$THIRD_PARTY"
    wget -q "https://archives.boost.io/release/${BOOST_VERSION}/source/boost_${BOOST_VERSION//./_}.tar.bz2"
    tar jxf boost_*.tar.bz2 && rm boost_*.tar.bz2
    mv boost_* boost
    cd boost && ./bootstrap.sh && ./b2 cxxflags=-fPIC -j"$JOBS"
fi

cd "$ROOT"

# Boost 1.89 and later ship the system library as header-only, so the linker
# needs an archive to satisfy -lboost_system.  The archive is created outside
# the build branch on purpose: a restored cache may predate it.
if [ -d "$THIRD_PARTY/boost/stage/lib" ] && [ ! -f "$THIRD_PARTY/boost/stage/lib/libboost_system.a" ]; then
    echo "=== adding the empty boost_system archive ==="
    printf '' > "$THIRD_PARTY/boost-empty.c"
    cc -c "$THIRD_PARTY/boost-empty.c" -o "$THIRD_PARTY/boost-empty.o"
    ar rcs "$THIRD_PARTY/boost/stage/lib/libboost_system.a" "$THIRD_PARTY/boost-empty.o"
    rm -f "$THIRD_PARTY/boost-empty.c" "$THIRD_PARTY/boost-empty.o"
fi

if [ ! -d "$THIRD_PARTY/openssl" ]; then
    echo "=== building OpenSSL $OPENSSL_VERSION ==="
    cd "$THIRD_PARTY"
    wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    tar zxf openssl-*.tar.gz && rm openssl-*.tar.gz
    mv openssl-* openssl
    cd openssl && ./Configure && make -j"$JOBS"
fi

if [ ! -d "$THIRD_PARTY/jemalloc" ]; then
    echo "=== building jemalloc $JEMALLOC_VERSION ==="
    cd "$THIRD_PARTY"
    wget -q "https://github.com/jemalloc/jemalloc/releases/download/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2"
    tar jxf jemalloc-*.tar.bz2 && rm jemalloc-*.tar.bz2
    mv jemalloc-* jemalloc
    cd jemalloc && ./autogen.sh --with-jemalloc-prefix=je_ && make -j"$JOBS"
fi

echo "third-party tree ready: $THIRD_PARTY"

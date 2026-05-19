# Corona constant-time analysis harness -- dudect bridge.
#
# Builds the cgo shim libraries (libcorona_verify, libcorona_combine)
# and links the C dudect harnesses against them.
#
# Prereqs (run once):
#   ./fetch.sh           # pulls dudect.h at the pinned commit
#
# Build:
#   make                 # both verify + combine
#   make verify          # just verify
#   make combine         # just combine
#
# Run:
#   ./dudect_verify      # smoke test (10000 samples/batch x 4 batches)
#   ./dudect_combine     # smoke test (2000 samples/batch x 4 batches)
#
# Full submission run (10^9 samples on a pinned-CPU quiet host):
#   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
#
# Hosts:
#   - x86_64 Linux/macOS: builds cleanly against upstream dudect.h
#   - aarch64 Linux/macOS: dudect_compat.h is force-included to supply
#     ARM equivalents of _mm_mfence() / __rdtsc(); see header.

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    SHLIB_EXT := dylib
    RPATH_FLAG := -Wl,-rpath,@loader_path
else
    SHLIB_EXT := so
    RPATH_FLAG := -Wl,-rpath,'$$ORIGIN'
endif

REPO_ROOT := $(shell cd ../.. && pwd)
DUDECT_HDR := dudect/src/dudect.h

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wno-unused-parameter -I. -Idudect/src
LDFLAGS ?=
LDLIBS  := -lm

ifeq ($(UNAME_M),arm64)
    CFLAGS += -include dudect_compat.h
endif
ifeq ($(UNAME_M),aarch64)
    CFLAGS += -include dudect_compat.h
endif

GO     ?= go
GOENV  := GOWORK=off CGO_ENABLED=1

.PHONY: all verify combine clean check-dudect

all: verify combine

libcorona_verify.$(SHLIB_EXT): verify_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags corona_verify_ct \
		-o libcorona_verify.$(SHLIB_EXT) \
		./verify_ct.go

libcorona_combine.$(SHLIB_EXT): combine_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags corona_combine_ct \
		-o libcorona_combine.$(SHLIB_EXT) \
		./combine_ct.go

dudect_verify: dudect_verify.c libcorona_verify.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_verify dudect_verify.c \
		-L. -lcorona_verify $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_combine: dudect_combine.c libcorona_combine.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_combine dudect_combine.c \
		-L. -lcorona_combine $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

verify: dudect_verify
combine: dudect_combine

check-dudect:
	@if [ ! -f $(DUDECT_HDR) ]; then \
		echo "==> dudect.h missing -- run ./fetch.sh"; \
		exit 1; \
	fi

clean:
	rm -f dudect_verify dudect_combine
	rm -f libcorona_verify.$(SHLIB_EXT) libcorona_verify.h
	rm -f libcorona_combine.$(SHLIB_EXT) libcorona_combine.h

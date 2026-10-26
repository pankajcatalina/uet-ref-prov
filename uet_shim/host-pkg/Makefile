# uet_shim - the uet_api.h boundary between the container and the QEMU guest
#
#   make xport_test   transport only: needs NO libfabric, NO uet tree
#   make host         uet_shim_host.o + friends, for the container
#   make guest        uet_shim_guest, for the VM
#   make shim_smoke   drives the shim as uet_provider does
#   make host-pkg     self-contained container package (no stack sources)
#
# transport: shm (shared memory, ~0.4 us) or vsock (~30 us, no ivshmem).
# Keep vsock as a differential diagnostic: a bug that reproduces on BOTH is
# in the RPC logic, not the region.
XPORT ?= shm
XPORT_OBJ = uet_shim_xport_$(XPORT).o

CC     = gcc
UETDIR = .

# Auto-discover a built libfabric by walking up from here, same convention
# as the stack's own Makefile. Only a WARNING: xport_test does not need it.
LIBFABRIC ?= $(shell \
	d=$(CURDIR); \
	while [ "$$d" != "/" ]; do \
		for c in $$d/libfabric*; do \
			[ -d "$$c/src/.libs" ] && { echo "$$c"; exit 0; }; \
		done; \
		d=$$(dirname $$d); \
	done)

ifeq ($(LIBFABRIC),)
$(warning no built libfabric found - only "make xport_test" will work)
$(warning set LIBFABRIC=/path/to/libfabric for the rest)
else
$(info using libfabric: $(LIBFABRIC))
endif
$(info transport: $(XPORT))

# The contract header and the transport need nothing but -I.
BARE_INCS = -I.
# Everything else needs uet_api.h/uet_addr.h and libfabric.
INCS = -I. -I$(UETDIR) \
       \
       -I$(LIBFABRIC) -I$(LIBFABRIC)/include

CFLAGS_BARE = -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -O2 $(BARE_INCS)
CFLAGS      = -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -O2 $(INCS)
LDLIBS      = -L$(LIBFABRIC)/src/.libs -lfabric -lpthread

# -rpath puts the library paths in the ELF rather than the environment, so
# they survive sudo (which makes the loader ignore LD_LIBRARY_PATH) and keep
# a distro libfabric from being picked up instead of the built one.
RPATH_LF = -Wl,-rpath,$(abspath $(LIBFABRIC)/src/.libs)
RPATH    = -Wl,-rpath,'$$ORIGIN/..' -Wl,-rpath,$(abspath $(UETDIR)) $(RPATH_LF)

BARE   = uet_shim_common.o $(XPORT_OBJ)
COMMON = $(BARE) uet_shim_info.o

all: host guest

# ---- checkpoint target: no libfabric, no uet tree ----
xport_test: xport_test.c $(BARE)
	$(CC) $(CFLAGS_BARE) $^ -o $@

uet_shim_common.o: uet_shim_common.c uet_shim.h
	$(CC) $(CFLAGS_BARE) -c $< -o $@
uet_shim_xport_shm.o: uet_shim_xport_shm.c uet_shim.h
	$(CC) $(CFLAGS_BARE) -c $< -o $@
uet_shim_xport_vsock.o: uet_shim_xport_vsock.c uet_shim.h
	$(CC) $(CFLAGS_BARE) -c $< -o $@

# ---- the rest needs libfabric and the uet headers ----
host: uet_shim_host.o $(COMMON)
	@echo "host objects ready: $^"
	@echo "link them with uet_provider INSTEAD of -luet_fabric"

guest: uet_shim_guest
uet_shim_guest: uet_shim_guest.o $(COMMON)
	$(CC) $^ -o $@ -L$(UETDIR) -luet_fabric $(LDLIBS) $(RPATH)

shim_smoke: shim_smoke.c uet_shim_host.o $(COMMON)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(RPATH_LF)

uet_shim_info.o: uet_shim_info.c uet_shim.h uet_shim_info.h
	$(CC) $(CFLAGS) -c $< -o $@
uet_shim_host.o: uet_shim_host.c uet_shim.h uet_shim_info.h
	$(CC) $(CFLAGS) -c $< -o $@
uet_shim_guest.o: uet_shim_guest.c uet_shim.h uet_shim_info.h
	$(CC) $(CFLAGS) -c $< -o $@

# ---------------------------------------------------------------- packaging
# A self-contained tree for the container. It carries the two API HEADERS it
# needs and NOTHING from the stack - no uet_api.c, no uet_pds*.c, no
# uet_sec.c, no nic_shim. SES and PDS exist only in the guest. The isolated
# build below proves that rather than asserting it.
HOST_PKG_FILES = uet_shim.h uet_shim_info.h uet_shim_info.c \
                 uet_shim_common.c uet_shim_xport_shm.c \
                 uet_shim_host.c shim_smoke.c xport_test.c

host-pkg:
	@rm -rf host-pkg && mkdir -p host-pkg
	@cp $(HOST_PKG_FILES) host-pkg/
	@cp $(UETDIR)/uet_api.h $(UETDIR)/uet_addr.h host-pkg/
	@sed -e 's|^UETDIR = .*|UETDIR = .|' \
	     -e 's|-I$$(UETDIR)/util ||'     -e 's|-I$$(UETDIR)/nic_shim ||' \
	     -e 's|-I$$(UETDIR)/imp_shim ||' -e 's|-I$$(UETDIR)/crypto ||' \
	     Makefile > host-pkg/Makefile
	@echo "host-pkg/ contains:"
	@ls -1 host-pkg/ | sed 's/^/  /'
	@echo "stack sources included: $$(ls host-pkg/ | grep -cE '^(uet_api|uet_pds|uet_sec)\.c|^nic_') (must be 0)"

clean:
	rm -f *.o uet_shim_guest xport_test shim_smoke
	rm -rf host-pkg

.PHONY: all host guest clean host-pkg

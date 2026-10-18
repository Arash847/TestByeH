#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor_reborn.elf

# 8.60 kernel .text dumper. Resumable: writes to /data and records a
# checkpoint after every chunk, so a power cycle costs at most one chunk.
#
#   make dump860          conservative: 4KB chunks, 24 reads per run
#   make dump860 FAST=1   faster:       16KB chunks, 96 reads per run
#
# Start with the conservative build for the first run.
DUMP_0860_ELF := byepervisor_dump_0860.elf

ifeq ($(FAST),1)
DUMP_FLAGS := -DDUMP_CHUNK=0x4000 -DDUMP_DELAY_US=150000 -DDUMP_MAX_READS=96
DUMP_0860_ELF := byepervisor_dump_0860_fast.elf
else
DUMP_FLAGS := -DDUMP_CHUNK=0x1000 -DDUMP_DELAY_US=200000 -DDUMP_MAX_READS=24
DUMP_0860_ELF := byepervisor_dump_0860.elf
endif

$(DUMP_0860_ELF): dump860.c util.c
	$(CC) $(CFLAGS) $(DUMP_FLAGS) -o $@ $(filter %.c,$^)

dump860: $(DUMP_0860_ELF)

# PML4 census. Reads the whole 4KB root page table in ONE transfer rather
# than 512 small ones, which is the pattern that destabilises this
# console. Diagnostic only.
PML4_0860_ELF := byepervisor_pml4_0860.elf

$(PML4_0860_ELF): probe_pml4.c util.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

probe-pml4: $(PML4_0860_ELF)

# Without this, make applies its builtin "%: %.c" rule to the dump860
# target, matching dump860.c, and links the source against the built ELF.
.PHONY: dump860 all clean test probe-pml4

PAYLOAD_DIR := break_hv_payload
PAYLOAD_HDR := $(PAYLOAD_DIR)/break_hv.h

CFLAGS := -Wall -Werror -Wno-unused-function -g -I./include -lSceSystemService

all: $(ELF)

$(PAYLOAD_HDR): $(PAYLOAD_DIR)/break_hv.c $(PAYLOAD_DIR)/entry.S $(PAYLOAD_DIR)/link.ld
	sh $(PAYLOAD_DIR)/build.sh

$(ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

clean:
	rm -f $(ELF)
	rm -f $(PAYLOAD_DIR)/break_hv.h $(PAYLOAD_DIR)/break_hv.bin $(PAYLOAD_DIR)/break_hv.elf $(PAYLOAD_DIR)/*.o

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"

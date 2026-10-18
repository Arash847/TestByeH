# Maintainer reports — ready to file

Everything below is derived from the user's own 8.60 slim console and
verified against their logs. No firmware, keys or dumps are included.

---

## Issue 1 — EchoStretch/Byepervisor-Reborn: unsupported firmware falls through

**Severity: the payload powers off an unsupported console.**

`main.c` guards the unsupported-firmware case but does not return, so
execution continues straight into the exploit with a NULL hook target,
enters rest mode, and the console hard-powers-off:

```c
  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Undetected firmware, exiting!\n");
    notifyf("[ERROR] Byepervisor Reborn\nFirmware is not supported :(\n");
  }              /* <-- no return */
```

PS5Dev/Byepervisor-Reborn has `return 1;` here. The `return` appears to
have been dropped when 12.xx support was added.

Reproduction: run any build on a firmware with no offset table — e.g.
8.60, or 14.xx — and the console powers off within a second, with the
"not supported" notification appearing first.

That is indistinguishable from the documented "exploit failed" shutdown
in the README, so it actively misleads anyone triporting.

A one-line `return 1;` fixes it.

---

## Issue 2 — EchoStretch/Byepervisor-Reborn: missing offset header includes

**Severity: the tree does not compile.**

`kdlsym.c` references `g_sym_map_1200/1202/1220/1240/1260/1270` and
`g_gadget_map_1340/1342`, but only includes:

```c
#include "offsets/13_00.h"
#include "offsets/13_20.h"
#include "offsets/13_60.h"
```

Building `768e8a1` fails with:

```
kdlsym.c:40:18: error: use of undeclared identifier 'g_gadget_map_1200';
                          did you mean 'g_gadget_map_1300'?
```

The 12.xx support commit added the header files and the switch cases but
not the includes. Adding the missing `#include` lines resolves it.

---

## Question 3 — 8.60 support

Is a Byepervisor port to 8.60 feasible? If it is not being worked on,
that is useful to know, and the findings below may save the effort.

### Measured on a slim (regular) 8.60 console, `fw = 0x08600004`

**1. `KERNEL_ADDRESS_TEXT_BASE` is wrong for 8.60.**

The SDK derives it as `KERNEL_ADDRESS_DATA_BASE - 0x0C70000` for the
`0x08600000` case, giving `0xFFFFFFFF81000000`. Walking proc 0's root
page table shows that address is **not mapped**:

```
PML4E[511] -> 0x00f00000230b5023   (valid PDPT, kernelmap)
PDPT[510]  -> 0x0000000000000000   (not present)
```

`0xFFFFFFFF81000000` resolves to PML4 index 511 and PDPT index 510, and
PDPTE[510] is zero. The kernel is mapped under PML4 slot 511 at
PDPT indices 0-3 and 511:

```
slot 511 sub   0 -> 0xFFFFFF8000000000
slot 511 sub   1 -> 0xFFFFFF8040000000
slot 511 sub   2 -> 0xFFFFFF8080000000
slot 511 sub   3 -> 0xFFFFFF80C0000000
slot 511 sub 511 -> recursive window
```

So any offset table anchored at the SDK's text base is anchored to an
unmapped address on 8.60. Worth checking whether other pre-12.x
firmwares are affected the same way, since the same table entry is
shared across the whole 8.x branch.

**2. The physmap is usable and is not XOM-blocked.**

Reading the entire 4KB PML4 through the direct map succeeds with `rc=0`.
Page-table reads work, and the three-level walk resolves to correctly
aligned physical addresses, for example `0x5ec00000`.

That matters because XOM blocks reads through the *virtual* mapping of
kernel `.text` — `copyout` on `0xFFFFFFFF81000000` returns immediately —
while physical access to the same page does not appear to be restricted.

This suggests the XOM bypass might not need the full VMCB sweep at all
on this firmware, or at least that the bypass could be validated against
physical reads rather than virtual ones. I have not established whether
text pages specifically are blocked physically; only that page-table
pages are not.

**3. Anchors already derived.**

`kstuff-lite` `8_60.h` is kdata-relative; its `allproc` (`0x2875D50`)
matches the SDK's `0x08600000` `ALLPROC` exactly, and the two tables agree
exactly on all four branches they share (8.x, 9.x, 11.x, 13.60). So the
anchors are sound and the conversion

```
ktext_offset = K + signed_kdata_offset
```

reproduces all three hardware-validated 11.60 symbols exactly
(`0xD30000 + 0x2E70300 = 0x3BA0300`, and likewise for `COMMON_TSS` and
`PMAP_STORE`). Applied to 8.60 with `K = 0xC70000`:

| Symbol | ktext offset |
|---|---|
| `KERNEL_SYM_IDT_ARRAY` | `0x3B23DF0` |
| `KERNEL_SYM_COMMON_TSS` | `0x3B26AD0` |
| `KERNEL_SYM_PMAP_STORE` | `0x3AB8848` |

Caveat: `K = 0xC70000` agrees with the SDK's own table, but that is the
table agreeing with itself, and item 1 shows the table is wrong at least
about the text base. It needs independent confirmation before use.

### What is still missing

4 data symbols (`DMPML4I`, `DMPDPI`, `PML4PML4I`, `DATA_CAVE`), all 5 text
symbols, and 15 of 21 gadgets. None are available from any public 8.60
source.

---

## Also relevant: soniciso1/relapse

Relapse covers 7.00-13.60, so it already supports 8.60. If it exposes
kernel text offsets, that may be the shortest route, and a question
there may be easier than a port.

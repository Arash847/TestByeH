/* 8.60 port stage-0 diagnostic: measure and validate K, and test whether
 * kernel text is readable.
 *
 * READ-ONLY. Writes nothing to kernel memory, installs no gate, touches
 * no IST entry, does not enter rest mode, does not access hypervisor
 * physical memory. Safe to run on a live 8.60 console.
 *
 * WHY THIS USES SDK CONSTANTS INSTEAD OF sidt/sgdt:
 * elfldr runs each payload as a userland (ring 3) process. UMIP is
 * enabled on this AMD part, so `sidt` and `sgdt` from ring 3 raise #GP.
 * Because each payload runs in its own process, that fault is silent --
 * the console shows nothing at all. An earlier revision of this probe
 * did exactly that and produced no output. K is instead taken from the
 * SDK's firmware-aware base constants, then validated structurally.
 *
 * K = kdata_base - ktext_base
 *
 * Validation is per-symbol rather than self-consistent: a wrong K makes
 * every anchor below fail its structural check simultaneously, so a
 * single bad constant cannot masquerade as agreement.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ps5/kernel.h>

#include "util.h"
#include "kdlsym.h"

/* kstuff-lite 8_60.h, kdata-relative. Confirmed kdata-relative by
 * cross-referencing the hardware-validated 11.60 tables, where IDT, TSS
 * and PMAP independently all yield K = 0xD30000.
 *
 * No ULL suffix: uint64_t is unsigned long on this target, and a ULL
 * literal widens arithmetic to unsigned long long, breaking -Wformat. */
#define KSTUFF_0860_ALLPROC    0x2875D50
#define KSTUFF_0860_IDT        0x2EB3DF0
#define KSTUFF_0860_GDT        0x2EB50D0
#define KSTUFF_0860_TSS_ARRAY  0x2EB6AD0
#define KSTUFF_0860_PCPU_ARRAY 0x2EC8A00
#define KSTUFF_0860_PMAP_STORE 0x2E48848

/* A value that plausibly points inside the kernel's own mapping. */
static int looks_like_kptr(uint64_t v, uint64_t tbase)
{
  return v >= tbase && v < (tbase + 0x10000000UL);
}

/* An IDT entry that is present, a 64-bit system gate, selector 0x08,
 * with the handler pointing back into kernel text. */
static int idt_entry_plausible(uint64_t e, uint64_t tbase)
{
  uint16_t lo  = (uint16_t)(e & 0xFFFF);
  uint16_t sel = (uint16_t)((e >> 16) & 0xFFFF);
  uint64_t h   = e >> 32;

  if (!(lo & 0x0001)) return 0;   /* present */
  if (!(lo & 0x0E00)) return 0;   /* system / interrupt gate */
  if (sel != 0x08)   return 0;   /* kernel code selector */
  return looks_like_kptr(h, tbase);
}

int main(void)
{
  uint64_t tbase, dbase, K;
  uint64_t idt_va, gdt_va, tss_va, pmap_va, allproc_va, pcpu_va;
  int i, idt_ok, gdt_ok, tss_ok, pcpu_ok, pmap_ok, proc_ok;
  int text_readable, all_zero, all_ones;
  uint64_t scratch[2] = { 0, 0 };
  uint64_t v;
  uint32_t passes;

  /* Print before doing anything else, so an immediate fault still leaves
   * a marker distinguishing "payload never started" from "payload
   * started and died later". */
  printf("[860-probe] alive: 8.60 stage-0 diagnostic\n");
  fflush(stdout);

  tbase = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  dbase = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  K    = dbase - tbase;

  printf("[860-probe] fw        = 0x%x\n",
         (unsigned int)(kernel_get_fw_version() & 0xffffffffU));
  printf("[860-probe] soc_id    = 0x%x\n", (unsigned int)sceKernelGetMainSocId());
  printf("[860-probe] ktext     = 0x%lx\n", (unsigned long)tbase);
  printf("[860-probe] kdata     = 0x%lx\n", (unsigned long)dbase);
  printf("[860-probe] K         = 0x%lx\n", (unsigned long)K);

  if (K < 0x100000 || K > 0x4000000) {
    printf("[860-probe] K outside plausible range -- base constants are wrong.\n");
    notifyf("[8.60 probe] FAILED\nK=0x%lx implausible", (unsigned long)K);
    return 1;
  }

  idt_va     = dbase + KSTUFF_0860_IDT;
  gdt_va     = dbase + KSTUFF_0860_GDT;
  tss_va     = dbase + KSTUFF_0860_TSS_ARRAY;
  pcpu_va    = dbase + KSTUFF_0860_PCPU_ARRAY;
  pmap_va    = dbase + KSTUFF_0860_PMAP_STORE;
  allproc_va = dbase + KSTUFF_0860_ALLPROC;

  /* ---- anchor 1: IDT ---------------------------------------------- */
  idt_ok = 0;
  for (i = 0; i < 256; i++) {
    v = kread64(idt_va + (uint64_t)i * 16);
    if (v != 0 && idt_entry_plausible(v, tbase))
      idt_ok++;
  }
  printf("[860-probe] IDT        @0x%lx plausible gates = %d/256\n",
         (unsigned long)idt_va, idt_ok);

  /* ---- anchor 2: GDT ---------------------------------------------- */
  gdt_ok = 0;
  for (i = 0; i < 64; i++) {
    uint64_t e = kread64(gdt_va + (uint64_t)i * 8);
    uint8_t type = (uint8_t)(e & 0xF);
    if ((e != 0) && (type == 0x9 || type == 0xB || type == 0xA || type == 0x2))
      gdt_ok++;
  }
  printf("[860-probe] GDT        @0x%lx descriptors    = %d\n",
         (unsigned long)gdt_va, gdt_ok);

  /* ---- corroboration: TSS, PCPU, pmap, allproc -------------------- */
  tss_ok = 0;
  for (i = 0; i < 16; i++) {
    v = kread64(tss_va + (uint64_t)i * 0xA0);
    if (looks_like_kptr(v, tbase))
      tss_ok++;
  }
  printf("[860-probe] TSS_ARRAY  @0x%lx stack ptrs ok  = %d/16\n",
         (unsigned long)tss_va, tss_ok);

  pcpu_ok = 0;
  for (i = 0; i < 16; i++) {
    v = kread64(pcpu_va + (uint64_t)i * 8);
    if (looks_like_kptr(v, tbase))
      pcpu_ok++;
  }
  printf("[860-probe] PCPU_ARRAY @0x%lx ptrs ok       = %d/16\n",
         (unsigned long)pcpu_va, pcpu_ok);

  v = kread64(pmap_va);
  pmap_ok = (v != 0);
  printf("[860-probe] PMAP_STORE @0x%lx value         = 0x%lx (%s)\n",
         (unsigned long)pmap_va, (unsigned long)v, pmap_ok ? "nonzero" : "ZERO");

  v = kread64(allproc_va);
  proc_ok = looks_like_kptr(v, tbase);
  printf("[860-probe] ALLPROC    @0x%lx head          = 0x%lx (%s)\n",
         (unsigned long)allproc_va, (unsigned long)v, proc_ok ? "kernel ptr" : "bad");

  /* ---- is kernel text readable? ----------------------------------- */
  /* util.c kread() unconditionally returns 0, so its return value says
   * nothing about success. Judge by content instead: unreadable text
   * reads back uniformly zero or uniformly 0xFF. The raw bytes are
   * printed so the result can be checked offline. */
  memset(scratch, 0, sizeof scratch);
  (void) kread(tbase, scratch, sizeof scratch);

  all_zero = 1;
  all_ones = 1;
  for (i = 0; i < (int)(sizeof scratch / sizeof scratch[0]); i++) {
    int b;
    for (b = 0; b < 8; b++) {
      uint8_t x = (uint8_t)(scratch[i] >> (b * 8));
      if (x)        all_zero = 0;
      if (x != 0xFF) all_ones = 0;
    }
  }
  text_readable = !(all_zero || all_ones);

  printf("[860-probe] ktext first 16 bytes:");
  for (i = 0; i < 16; i++)
    printf(" %02x", (unsigned int)((uint8_t *)scratch)[i]);
  printf("\n");
  printf("[860-probe] ktext raw qwords: %016lx %016lx\n",
         (unsigned long)scratch[0], (unsigned long)scratch[1]);
  printf("[860-probe] ktext %s\n",
         text_readable ? "READABLE (content is neither zero nor 0xFF)"
                       : (all_zero ? "reads ALL ZERO -> not readable"
                                   : "reads ALL 0xFF -> not readable"));

  passes = (idt_ok > 0) + (gdt_ok > 0) + (tss_ok == 16) + (pcpu_ok == 16) +
           (pmap_ok) + (proc_ok);
  printf("[860-probe] anchors validated: %u/6\n", (unsigned int)passes);
  printf("[860-probe] done, wrote nothing\n");

#ifdef DUMP_KTEXT_SIZE
  if (text_readable && DUMP_KTEXT_SIZE > 0) {
    uint64_t done = 0;
    static uint8_t chunk[0x1000];
    printf("KTDUMP1 %lx %x\n", (unsigned long)tbase, (unsigned int)DUMP_KTEXT_SIZE);
    while (done < (uint64_t)DUMP_KTEXT_SIZE) {
      uint64_t n = ((uint64_t)DUMP_KTEXT_SIZE - done) < sizeof chunk
                     ? ((uint64_t)DUMP_KTEXT_SIZE - done) : sizeof chunk;
      (void) kread(tbase + done, chunk, n);
      if (fwrite(chunk, 1, n, stdout) != n) {
        printf("\n[dump] short write at 0x%lx\n", (unsigned long)done);
        break;
      }
      done += n;
    }
    printf("\nKTDONE1\n");
    printf("[860-probe] dump complete: 0x%lx bytes\n", (unsigned long)done);
  }
#endif

  fflush(stdout);

  if (passes >= 5)
    notifyf("[8.60 probe] OK %u/6 anchors\nK=0x%lx\nktext %s",
            (unsigned int)passes, (unsigned long)K,
            text_readable ? "readable" : "BLOCKED");
  else
    notifyf("[8.60 probe] WEAK %u/6 anchors\nK=0x%lx",
            (unsigned int)passes, (unsigned long)K);

  return 0;
}

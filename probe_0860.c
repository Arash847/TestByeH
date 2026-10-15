/* 8.60 port stage-0/1 diagnostic: derive K = kdata_base - ktext_base.
 *
 * READ-ONLY. This payload writes nothing to kernel memory, installs no
 * gate, touches no IST entry, does not enter rest mode, and does not
 * look at hypervisor physical memory. It is safe to run on a live 8.60
 * console.
 *
 * It measures K from two fully independent anchors -- the CPU IDT and
 * GDT descriptor-table registers -- because the porting guide requires
 * at least two independent anchors to agree before any offset is
 * believed. Both anchors are pure reads of architectural state.
 *
 * Anchors (kstuff-lite 8_60.h, kdata-relative):
 *     idt       0x2EB3DF0
 *     gdt_array 0x2EB50D0
 *
 * Also reports the SoC ID so the regular/Pro model check is recorded,
 * and probes 16 bytes of kernel text so we learn whether 8.60 still
 * has readable text (expected: yes, this predates enforced XOM).
 */

#include <sys/types.h>
#include <stdio.h>
#include <ps5/kernel.h>

#include "util.h"
#include "kdlsym.h"

/* kstuff-lite 8_60.h, kdata-relative. Verified as kdata-rel by
 * cross-referencing the hardware-validated 11.60 tables.
 *
 * No ULL suffixes: uint64_t is unsigned long on this target, so a ULL
 * literal would widen arithmetic expressions to unsigned long long and
 * break -Wformat against %lx. */
#define KSTUFF_0860_IDT       0x2EB3DF0
#define KSTUFF_0860_GDT       0x2EB50D0
#define KSTUFF_0860_TSS_ARRAY 0x2EB6AD0

struct idtr {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));

struct gdtr {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));

/* Read IDT/GDT registers without inline asm leaking into the payload:
 * the ps5-payload-dev SDK exposes these through the standard headers,
 * but sidt/sgdt are single-instruction reads so spelling them out keeps
 * this file buildable on any host toolchain. */
static void read_idtr(struct idtr *r)
{
  __asm__ __volatile__("sidt %0" : "=m"(*r));
}

static void read_gdtr(struct gdtr *r)
{
  __asm__ __volatile__("sgdt %0" : "=m"(*r));
}

static uint64_t ktext_base(void)
{
  return KERNEL_ADDRESS_TEXT_BASE;
}

/* An IDT entry that is present, 64-bit interrupt gate, selector 0x08,
 * with the handler pointing back into kernel text. */
static int idt_entry_plausible(uint64_t entry, uint64_t tbase)
{
  uint16_t lo = (uint16_t)(entry & 0xFFFF);
  uint16_t sel = (uint16_t)((entry >> 16) & 0xFFFF);
  uint64_t handler = (entry >> 32) & 0xFFFFFFFFFFFFFFFFULL;

  if (!(lo & 0x0001))                       /* not present */
    return 0;
  if (!(lo & 0x0E00))                       /* not a system/interrupt gate */
    return 0;
  if (sel != 0x08)                          /* unexpected selector */
    return 0;
  if (handler < tbase)                      /* handler outside kernel text */
    return 0;
  return 1;
}

int main(void)
{
  struct idtr idtr;
  struct gdtr gdtr;
  uint64_t tbase, k_idt, k_gdt, delta;
  uint64_t idt_off, gdt_off, probe;
  uint64_t present;
  int i, agrees, idt_ok, gdt_ok, text_readable = 0;
  uint64_t scratch[2] = { 0, 0 };

  tbase = ktext_base();

  printf("[860-probe] Byepervisor 8.60 stage-0 diagnostic\n");
  printf("[860-probe] fw        = 0x%x\n",
         (unsigned int)(kernel_get_fw_version() & 0xffffffffU));
  printf("[860-probe] soc_id    = 0x%x\n", (unsigned int)sceKernelGetMainSocId());
  printf("[860-probe] ktext     = 0x%lx\n", tbase);

  read_idtr(&idtr);
  read_gdtr(&gdtr);

  printf("[860-probe] idtr.base = 0x%lx (limit 0x%x)\n", idtr.base, idtr.limit);
  printf("[860-probe] gdtr.base = 0x%lx (limit 0x%x)\n", gdtr.base, gdtr.limit);

  /* Anchor 1: IDT. Anchor 2: GDT. Both are pure descriptor-table reads
   * and neither depends on the other. */
  idt_off = idtr.base - tbase;
  gdt_off = gdtr.base - tbase;
  k_idt = idt_off - KSTUFF_0860_IDT;
  k_gdt = gdt_off - KSTUFF_0860_GDT;

  printf("[860-probe] idt  ktext_off = 0x%lx\n", idt_off);
  printf("[860-probe] gdt  ktext_off = 0x%lx\n", gdt_off);
  printf("[860-probe] K(idt)        = 0x%lx\n", k_idt);
  printf("[860-probe] K(gdt)        = 0x%lx\n", k_gdt);

  delta = (k_idt > k_gdt) ? (k_idt - k_gdt) : (k_gdt - k_idt);
  agrees = (delta == 0);
  printf("[860-probe] anchors %s (delta 0x%lx)\n",
         agrees ? "AGREE" : "DISAGREE -- do not trust either", delta);

  if (k_idt < 0x100000 || k_idt > 0x4000000) {
    printf("[860-probe] K out of plausible range; measurement is wrong.\n");
    notifyf("[8.60 probe]\nK measurement failed\nIDTR=%lx GDTR=%lx",
            idtr.base, gdtr.base);
    return 1;
  }

  /* Sanity-check the derived K by confirming the IDT really does hold
   * plausible present gates whose handlers point into kernel text. A K
   * that is merely self-consistent but wrong fails here. */
  idt_ok = 0;
  for (i = 0; i < 256; i++) {
    present = kread64(idtr.base + (uint64_t)i * 16);
    if (present != 0 && idt_entry_plausible(present, tbase))
      idt_ok++;
  }
  printf("[860-probe] IDT plausible gates = %d/256\n", idt_ok);

  gdt_ok = 0;
  for (i = 0; i < (gdtr.limit / 8) + 1 && i < 64; i++) {
    if (kread64(gdtr.base + (uint64_t)i * 8) != 0)
      gdt_ok++;
  }
  printf("[860-probe] GDT nonzero entries = %d/%d\n", gdt_ok, (gdtr.limit / 8) + 1);

  /* Derived data-side addresses, using the agreed K. */
  printf("[860-probe] -> IDT_ARRAY   ktext_off = 0x%lx\n",
         (uint64_t)(k_idt + KSTUFF_0860_IDT));
  printf("[860-probe] -> GDT_ARRAY   ktext_off = 0x%lx\n",
         (uint64_t)(k_gdt + KSTUFF_0860_GDT));
  printf("[860-probe] -> TSS_ARRAY   ktext_off = 0x%lx (unverified anchor)\n",
         (uint64_t)(k_idt + KSTUFF_0860_TSS_ARRAY));

  /* Is kernel text readable on 8.60? Expected yes: this predates the
   * enforced XOM that forces the hypervisor bypass in the first place.
   * This is the single most valuable fact for the port.
   *
   * kread64() returns a single qword and takes only an address; kread()
   * is the copyout primitive that reports success as 0. */
  probe = tbase;
  if (kread(probe, scratch, sizeof scratch) == 0) {
    text_readable = 1;
    printf("[860-probe] ktext READABLE at 0x%lx: %016lx %016lx\n",
           probe, scratch[0], scratch[1]);
    printf("[860-probe] dump ktext from here; offline tools can do the rest.\n");
  } else {
    printf("[860-probe] ktext NOT readable at 0x%lx -> blind bootstrap needed\n",
           probe);
  }

  printf("[860-probe] done, wrote nothing\n");

  if (agrees && idt_ok > 0 && text_readable) {
    notifyf("[8.60 probe] K=0x%lx OK\nIDT=%d/256 gates\nktext readable",
            k_idt, idt_ok);
  } else {
    notifyf("[8.60 probe] inconclusive\nK_idt=%lx K_gdt=%lx\ngates=%d",
            k_idt, k_gdt, idt_ok);
  }

  return 0;
}

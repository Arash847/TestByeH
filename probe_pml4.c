/* PML4 census: read the entire root page table in one transfer.
 *
 * WHY
 * ---
 * The dump attempt now has a correct, canonical direct map:
 *
 *     pm_pml4  = 0xffff8d072424d000
 *     pm_cr3   = 0x2424d000
 *     dmap     = pm_pml4 - pm_cr3 = 0xffff8d0700000000
 *
 * and dmap + pm_cr3 lands exactly on pm_pml4, as it should. What fails is
 * the per-entry walk, and a per-entry walk is 512 small copyouts -- which
 * is precisely the pattern that has been destabilising this console.
 *
 * So read the whole PML4 as ONE 4KB copyout, save it, and summarise which
 * slots are populated. One transfer, and the answer is unambiguous rather
 * than inferred from a failed walk.
 *
 * READ-ONLY. Writes go only to /data.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

#include "util.h"

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define OFF_PROC_P_VMSPACE  0x200
#define OFF_VMSPACE_VM_PMAP 0x2E8
#define PMAP_PML4_OFF       0x20
#define PMAP_CR3_OFF        0x28

#define KTEXT_BASE 0xFFFFFFFF81000000ULL

#define DIAG_PATH "/data/bye860_diag.txt"
#define PML4_PATH "/data/bye860_pml4.bin"

static FILE *g_diag;

static void diag(const char *fmt, ...)
{
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  fputs(buf, stdout);
  fflush(stdout);
  if (!g_diag)
    g_diag = fopen(DIAG_PATH, "w");
  if (g_diag) {
    fputs(buf, g_diag);
    fflush(g_diag);
  }
}

int main(void)
{
  static uint8_t pml4[4096];
  uint64_t proc, vmspace, pm_pml4, pm_cr3, dmap;
  int i, rc, present = 0;

  diag("[pml4] census start\n");

  proc = kernel_get_proc(0);
  diag("[pml4] proc(0)     = 0x%lx\n", (unsigned long)proc);
  if (!proc)
    return 1;

  if (kernel_copyout(proc + OFF_PROC_P_VMSPACE, &vmspace, sizeof vmspace)) {
    diag("[pml4] cannot read vmspace\n");
    return 1;
  }
  if (kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_PML4_OFF,
                     &pm_pml4, sizeof pm_pml4) ||
      kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_CR3_OFF,
                     &pm_cr3, sizeof pm_cr3)) {
    diag("[pml4] cannot read pmap roots\n");
    return 1;
  }

  dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  if (!dmap)
    dmap = pm_pml4 - pm_cr3;

  diag("[pml4] pm_pml4    = 0x%lx\n", (unsigned long)pm_pml4);
  diag("[pml4] pm_cr3     = 0x%lx\n", (unsigned long)pm_cr3);
  diag("[pml4] dmap       = 0x%lx\n", (unsigned long)dmap);
  diag("[pml4] dmap+cr3   = 0x%lx (should equal pm_pml4)\n",
       (unsigned long)(dmap + pm_cr3));
  diag("[pml4] match      = %s\n",
       (dmap + pm_cr3) == pm_pml4 ? "YES" : "NO");
  diag("[pml4] ktext PML4 index for 0x%lx = %lu\n",
       (unsigned long)KTEXT_BASE, (KTEXT_BASE >> 39) & 0x1FF);
  diag("\n");

  /* One transfer for the whole table. */
  rc = (int)kernel_copyout(dmap + pm_cr3, pml4, sizeof pml4);
  diag("[pml4] whole-table copyout rc=%d\n", rc);
  if (rc != 0) {
    diag("[pml4] physmap reads are blocked; no PML4 census possible.\n");
    diag("[pml4] that implies XOM blocks the physmap too, so this whole\n");
    diag("[pml4] approach is closed and the offsets must come from\n");
    diag("[pml4] execution evidence instead of a dump.\n");
    notifyf("[pml4] physmap BLOCKED\napproach closed");
    return 2;
  }

  {
    FILE *f = fopen(PML4_PATH, "wb");
    if (f) {
      fwrite(pml4, 1, sizeof pml4, f);
      fflush(f);
      fclose(f);
      diag("[pml4] saved 4096 bytes to %s\n", PML4_PATH);
    }
  }

  diag("[pml4] populated PML4 slots:\n");
  for (i = 0; i < 512; i++) {
    uint64_t e;
    memcpy(&e, &pml4[i * 8], sizeof e);
    if (!(e & 1ULL))
      continue;
    present++;
    /* Print the slots that matter for kernel text first, then the rest. */
    if (i == 511 || i == 256 || i == 0)
      diag("[pml4]   [%3d] 0x%016lx  <== kernel-text slot%s\n",
           i, (unsigned long)e,
           ((KTEXT_BASE >> 39) & 0x1FF) == (uint64_t)i ? " (MATCH)" : "");
  }

  diag("[pml4] %d populated slots total\n", present);

  {
    uint64_t idx = (KTEXT_BASE >> 39) & 0x1FF;
    uint64_t e = 0;
    memcpy(&e, &pml4[idx * 8], sizeof e);
    diag("[pml4] entry[%lu] = 0x%016lx present=%d\n",
         (unsigned long)idx, (unsigned long)e, (int)(e & 1));
  }

  /* ---- walk trace -------------------------------------------------
   * The physmap read works, so every level should be reachable. The
   * dumper only reported "walk failed" without naming the level, so trace
   * it: table base, index used, entry read back, and where it goes next.
   * This pins the failing level instead of inferring it. */
  diag("\n[pml4] --- walk trace for 0x%lx ---\n", (unsigned long)KTEXT_BASE);
  {
    uint64_t tbl = pm_cr3 & 0x000FFFFFFFFFF000ULL;
    int lvl;

    for (lvl = 0; lvl < 5; lvl++) {
      int      shift = 39 - 9 * lvl;
      uint64_t index = (KTEXT_BASE >> shift) & 0x1FFULL;
      uint64_t addr  = dmap + tbl + index * 8;
      uint64_t e     = 0;
      int      rc    = (int)kernel_copyout(addr, &e, sizeof e);

      diag("[pml4] lvl%d shift=%2d idx=%3lu addr=0x%lx rc=%d",
           lvl, shift, (unsigned long)index, (unsigned long)addr, rc);

      if (rc != 0) {
        diag("  <== READ FAILED here; physmap may not cover table 0x%lx\n",
             (unsigned long)tbl);
        break;
      }

      diag("  entry=0x%016lx P=%d W=%d PS=%d U=%d\n", (unsigned long)e,
           (int)(e & 1), (int)((e >> 1) & 1), (int)((e >> 7) & 1),
           (int)((e >> 2) & 1));

      if (!(e & 1ULL)) {
        diag("  <== NOT PRESENT here\n");
        break;
      }

      if ((e & 0x80ULL) || shift == 12) {
        uint64_t leaf;
        uint8_t  probe16[16];
        int      rc2;

        if (shift == 12)
          leaf = (e & 0x000FFFFFFFFFF000ULL) | (KTEXT_BASE & 0xFFF);
        else
          leaf = (e & ((1ULL << 52) - (1ULL << shift))) |
                 (KTEXT_BASE & ((1ULL << shift) - 1));

        diag("[pml4] leaf physical = 0x%lx\n", (unsigned long)leaf);
        diag("[pml4] physmap read addr = 0x%lx\n", (unsigned long)(dmap + leaf));

        rc2 = (int)kernel_copyout(dmap + leaf, probe16, sizeof probe16);
        diag("[pml4] text read rc=%d\n", rc2);
        if (rc2 == 0) {
          int b;
          diag("[pml4] first bytes:");
          for (b = 0; b < 16; b++)
            diag(" %02x", probe16[b]);
          diag("\n[pml4] if these are x86-64, the XOM bypass works\n");
        }
        break;
      }

      tbl = e & 0x000FFFFFFFFFF000ULL;
    }
  }

  notifyf("[pml4] census done\n%lu slots present\nroot=0x%lx",
          (unsigned long)present, (unsigned long)pm_cr3);
  return 0;
}

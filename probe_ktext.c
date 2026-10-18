/* Locate kernel .text by hunting through the real kernelmap.
 *
 * WHAT THE CENSUS ESTABLISHED
 * ---------------------------
 * PML4E[511] is the kernelmap slot. Under it, PDPT indices 0,1,2,3 and
 * 511 are live. Restoring the canonical high half that the earlier census
 * printout dropped:
 *
 *     slot 511 sub   0 -> 0xFFFFFF8000000000
 *     slot 511 sub   1 -> 0xFFFFFF8040000000
 *     slot 511 sub   2 -> 0xFFFFFF8080000000
 *     slot 511 sub   3 -> 0xFFFFFF80C0000000
 *     slot 511 sub 511 -> recursive window
 *
 * KERNEL_ADDRESS_TEXT_BASE, 0xFFFFFFFF81000000, resolves to PML4 index 511
 * and PDPT index 510 -- and PDPTE[510] reads back as zero. The SDK base
 * is not mapped on this firmware, which is why every earlier dump range
 * pointed at nothing.
 *
 * The physmap works: a whole 4KB PML4 comes back with rc=0. XOM guards the
 * virtual mapping of .text, not physical access, so the way in is to walk
 * to a physical address and read through dmap.
 *
 * TWO EARLIER VERSIONS WERE WRONG, both worth recording:
 *
 *  - It treated any present entry as a leaf. A value ending 0x63 has PS
 *    clear, meaning it points at the next level instead of being one, so
 *    that read returned the next page TABLE and 64 zero bytes.
 *  - It then followed only the FIRST populated entry at each level. That
 *    dead-ends: PD[0] is present but its page table has no present
 *    entries, so that particular 2MB region is simply unmapped.
 *
 * So this iterates populated entries across the whole region, reads each
 * candidate page, and stops at the first one with real content.
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

#define KERNELMAP_BASE 0xFFFFFF8000000000ULL

/* Cap on how many page directories to open, to bound transfers. */
#ifndef MAX_PDE
#define MAX_PDE 16
#endif

#define DIAG_PATH "/data/bye860_diag.txt"

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
  static uint8_t pd[4096];
  static uint8_t pt[4096];
  static uint8_t page[64];
  uint64_t proc, vmspace, pm_pml4, pm_cr3, dmap, km_phys, leaf;
  int      i, tried = 0, found = 0;

  diag("[ktext] locate kernel text via the real kernelmap\n");

  proc = kernel_get_proc(0);
  if (!proc) {
    diag("[ktext] no proc 0\n");
    return 1;
  }

  if (kernel_copyout(proc + OFF_PROC_P_VMSPACE, &vmspace, sizeof vmspace) ||
      kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_PML4_OFF,
                     &pm_pml4, sizeof pm_pml4) ||
      kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_CR3_OFF,
                     &pm_cr3, sizeof pm_cr3)) {
    diag("[ktext] cannot read pmap roots\n");
    return 1;
  }

  dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  if (!dmap)
    dmap = pm_pml4 - pm_cr3;

  diag("[ktext] dmap=0x%lx pm_cr3=0x%lx\n",
       (unsigned long)dmap, (unsigned long)pm_cr3);

  if (kernel_copyout(dmap + pm_cr3, pml4, sizeof pml4) != 0) {
    diag("[ktext] cannot read PML4\n");
    return 1;
  }

  {
    uint64_t e511;
    memcpy(&e511, &pml4[511 * 8], sizeof e511);
    km_phys = e511 & 0x000FFFFFFFFFF000ULL;
    diag("[ktext] PML4E[511] = 0x%016llx -> PDPT phys 0x%lx\n",
         (unsigned long long)e511, (unsigned long)km_phys);
  }

  diag("[ktext] --- hunting for the first real kernel page ---\n");

  if (kernel_copyout(dmap + km_phys, pd, sizeof pd) != 0) {
    diag("[ktext] cannot read PDPT at 0x%lx\n", (unsigned long)km_phys);
    return 2;
  }

  for (i = 0; i < 512 && !found; i++) {
    uint64_t pde;

    memcpy(&pde, &pd[i * 8], sizeof pde);
    if (!(pde & 1ULL))
      continue;

    /* A 1GB page at PDPT level is itself a leaf. */
    if (pde & 0x80ULL) {
      leaf = (pde & (((1ULL << 52) - (1ULL << 30)))) | ((uint64_t)i << 30);
      diag("[ktext] PDPT[%d] is a 1GB page -> phys 0x%lx\n",
           i, (unsigned long)leaf);
      found = 1;
      break;
    }

    if (tried >= MAX_PDE)
      continue;

    {
      uint64_t pt_phys = pde & 0x000FFFFFFFFFF000ULL;
      int      j, pte_count = 0;

      if (kernel_copyout(dmap + pt_phys, pt, sizeof pt) != 0)
        continue;

      for (j = 0; j < 512; j++) {
        uint64_t e;
        memcpy(&e, &pt[j * 8], sizeof e);
        if (e & 1ULL)
          pte_count++;
      }

      diag("[ktext] PDPT[%d] -> PD 0x%lx : %d present PDE(s)\n",
           i, (unsigned long)pt_phys, pte_count);

      /* Populated PD with an empty page table: the region is unmapped. */
      if (!pte_count)
        continue;

      tried++;

      for (j = 0; j < 512 && !found; j++) {
        uint64_t pte, cand;
        int      rc, nz = 0, b;

        memcpy(&pte, &pt[j * 8], sizeof pte);
        if (!(pte & 1ULL))
          continue;

        /* A 2MB page at PD level is a leaf too. */
        if (pte & 0x80ULL) {
          cand = (pte & (((1ULL << 52) - (1ULL << 21)))) |
                 ((uint64_t)j << 21);
        } else {
          cand = (pte & 0x000FFFFFFFFFF000ULL) | (uint64_t)j;
        }

        rc = (int)kernel_copyout(dmap + cand, page, sizeof page);
        if (rc != 0)
          continue;

        for (b = 0; b < 64; b++)
          if (page[b])
            nz++;
        if (!nz)
          continue;

        leaf = cand;
        found = 1;
        diag("[ktext]   PDPT[%d] PDE[%d] -> phys 0x%lx\n",
             i, j, (unsigned long)cand);
        diag("[ktext]   VA       = 0x%lx\n",
             (unsigned long)(KERNELMAP_BASE + ((uint64_t)i << 30) +
                             ((uint64_t)j << 21)));
        diag("[ktext]   content: %d/64 non-zero bytes\n", nz);
        diag("[ktext]   first 32 bytes:");
        for (b = 0; b < 32; b++)
          diag(" %02x", page[b]);
        diag("\n");
      }
    }
  }

  if (!found) {
    diag("[ktext] no page with content found (opened %d PDs)\n", tried);
    notifyf("[ktext] no content found\nopened %d PDs", tried);
    return 2;
  }

  diag("[ktext] opened %d PDs to find content\n", tried);
  diag("[ktext] FIRST REAL PAGE physical = 0x%lx\n", (unsigned long)leaf);

  {
    FILE *f = fopen("/data/bye860_text_head.bin", "wb");
    if (f) {
      uint8_t again[64];
      if (kernel_copyout(dmap + leaf, again, sizeof again) == 0) {
        fwrite(again, 1, sizeof again, f);
        fflush(f);
        fclose(f);
        diag("[ktext] saved 64 bytes to bye860_text_head.bin\n");
      } else {
        fclose(f);
      }
    }
  }

  notifyf("[ktext] found physical 0x%lx\nbytes saved to /data", (unsigned long)leaf);
  return 0;
}

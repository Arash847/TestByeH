/* Locate kernel .text by walking the real kernelmap, then read it.
 *
 * WHAT THE CENSUS ESTABLISHED
 * ---------------------------
 * PML4E[511] is the kernelmap slot. Under it, PDPT indices 0,1,2,3 and
 * 511 are live. Restoring the canonical high half that the census's "va~"
 * printout dropped:
 *
 *     slot 511 sub 0 -> 0xFFFFFF8000000000
 *     slot 511 sub 1 -> 0xFFFFFF8040000000
 *     slot 511 sub 2 -> 0xFFFFFF8080000000
 *     slot 511 sub 3 -> 0xFFFFFF80C0000000
 *     slot 511 sub 511 -> 0xFFFFC0000000 (recursive)
 *
 * So the kernelmap base is 0xFFFFFF8000000000. KERNEL_ADDRESS_TEXT_BASE,
 * 0xFFFFFFFF81000000, resolves to PML4 index 511 and PDPT index 510 --
 * and PDPTE[510] reads back as zero. The SDK base is simply not mapped on
 * this firmware, which is why every earlier dump range pointed at nothing.
 *
 * The physmap itself works: a whole 4KB PML4 came back with rc=0. XOM
 * guards the virtual mapping of .text, not physical access, so walking to
 * a physical address and reading through dmap is the way in.
 *
 * This walks from the real kernelmap base, finds the first present leaf,
 * and reads through the physmap. If the bytes come back as x86-64 then
 * kernel text is located and dumping becomes possible.
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

/* Full x86-64 walk with logging. Returns physical address, or ~0. */
static uint64_t walk(uint64_t va, uint64_t dmap, uint64_t root, int trace)
{
  uint64_t tbl = root & 0x000FFFFFFFFFF000ULL;
  int lvl;

  for (lvl = 0; lvl < 5; lvl++) {
    int      shift = 39 - 9 * lvl;
    uint64_t index = (va >> shift) & 0x1FFULL;
    uint64_t e = 0;
    int      rc;

    rc = (int)kernel_copyout(dmap + tbl + index * 8, &e, sizeof e);
    if (trace)
      diag("[ktext]   lvl%d idx=%3llu tbl=0x%lx rc=%d entry=0x%016llx\n",
           lvl, (unsigned long long)index, (unsigned long)tbl, rc,
           (unsigned long long)e);

    if (rc != 0 || !(e & 1ULL))
      return (uint64_t)-1;

    if ((e & 0x80ULL) || shift == 12) {
      uint64_t leaf;
      if (shift == 12)
        leaf = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
      else
        leaf = (e & ((1ULL << 52) - (1ULL << shift))) |
               (va & ((1ULL << shift) - 1));
      if (trace)
        diag("[ktext]   leaf phys=0x%lx  (physmap read at 0x%lx)\n",
             (unsigned long)leaf, (unsigned long)(dmap + leaf));
      return leaf;
    }
    tbl = e & 0x000FFFFFFFFFF000ULL;
  }
  return (uint64_t)-1;
}

int main(void)
{
  static uint8_t pml4[4096];
  uint64_t proc, vmspace, pm_pml4, pm_cr3, dmap;
  uint64_t km_phys, leaf;

  diag("[ktext] locate kernel text via the real kernelmap\n");

  proc = kernel_get_proc(0);
  if (!proc) { diag("[ktext] no proc 0\n"); return 1; }
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

  /* PML4E[511] is the kernelmap slot. */
  {
    uint64_t e511;
    memcpy(&e511, &pml4[511 * 8], sizeof e511);
    km_phys = e511 & 0x000FFFFFFFFFF000ULL;
    diag("[ktext] PML4E[511] = 0x%016llx -> PDPT phys 0x%lx\n",
         (unsigned long long)e511, (unsigned long)km_phys);
  }

  /* Scanning beats probing one index.
   *
   * The walk reaches three levels cleanly; PT[0] is simply a hole. Every
   * 2MB region probed had page index 0 unmapped, which says nothing about
   * the rest of the region -- kernel text does not begin at a 2MB
   * boundary plus zero. So read each level as a whole table (one 4KB
   * read) and find the lowest PRESENT entry, then read what is there. */
  diag("[ktext] --- scanning kernelmap for the first mapped page ---\n");
  {
    static uint8_t pd[4096], pt[4096];
    int i, found = 0;

    if (kernel_copyout(dmap + km_phys, pd, sizeof pd) != 0) {
      diag("[ktext] cannot read PDPT at 0x%lx\n", (unsigned long)km_phys);
      return 2;
    }

    for (i = 0; i < 512 && !found; i++) {
      uint64_t pde;
      memcpy(&pde, &pd[i * 8], sizeof pde);
      if (!(pde & 1ULL))
        continue;

      if (pde & 0x80ULL) {
        leaf = (pde & (((1ULL << 52) - (1ULL << 21)))) | ((uint64_t)i << 21);
        diag("[ktext] PDPT[%d] is a 2MB page -> phys 0x%lx\n",
             i, (unsigned long)leaf);
        found = 1;
        break;
      }

      {
        uint64_t pt_phys = pde & 0x000FFFFFFFFFF000ULL;
        int j;
        if (kernel_copyout(dmap + pt_phys, pt, sizeof pt) != 0)
          continue;
        for (j = 0; j < 512; j++) {
          uint64_t pte;
          memcpy(&pte, &pt[j * 8], sizeof pte);
          if (!(pte & 1ULL))
            continue;
          leaf = (pte & 0x000FFFFFFFFFF000ULL) | (uint64_t)j;
          diag("[ktext] PDPT[%d] -> PT 0x%lx, first present PTE[%d]\n",
               i, (unsigned long)pt_phys, j);
          diag("[ktext]   VA   = 0x%lx\n",
               (unsigned long)(KERNELMAP_BASE + ((uint64_t)i << 30) +
                               ((uint64_t)j << 12)));
          diag("[ktext]   phys = 0x%lx\n", (unsigned long)leaf);
          found = 1;
          break;
        }
      }
    }

    if (!found) {
      diag("[ktext] no present leaf in the first 1GB of kernelmap\n");
      notifyf("[ktext] no mapped page\nin first 1GB of kernelmap");
      return 2;
    }
  }

  diag("[ktext] FIRST MAPPED physical = 0x%lx\n", (unsigned long)leaf);

  {
    uint8_t probe64[64];
    int      rc = (int)kernel_copyout(dmap + leaf, probe64, sizeof probe64);
    int      b, looks = 0;

    diag("[ktext] text read rc=%d\n", rc);
    if (rc != 0) {
      diag("[ktext] physmap read of text refused; XOM may cover physical too\n");
      notifyf("[ktext] physmap text read refused");
      return 3;
    }

    diag("[ktext] first 64 bytes:");
    for (b = 0; b < 64; b++) {
      if (b % 16 == 0)
        diag("\n   ");
      diag(" %02x", probe64[b]);
    }
    diag("\n");

    /* Cheap plausibility: count bytes that look like x86-64 opcode-ish
     * values. A random or XOM-poisoned span looks very different. */
    for (b = 0; b < 64; b++)
      if (probe64[b] != 0x00 && probe64[b] != 0xFF)
        looks++;
    diag("[ktext] non-zero/non-FF bytes = %d/64\n", looks);

    {
      FILE *f = fopen("/data/bye860_text_head.bin", "wb");
      if (f) {
        fwrite(probe64, 1, sizeof probe64, f);
        fflush(f);
        fclose(f);
        diag("[ktext] saved 64 bytes to bye860_text_head.bin\n");
      }
    }
  }

  notifyf("[ktext] found physical 0x%lx\nfirst 64 bytes saved",
          (unsigned long)leaf);
  return 0;
}

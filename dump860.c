/* 8.60 kernel .text dumper -- reads through the physical direct map.
 *
 * WHY THE DIRECT MAP
 * ------------------
 * The first build read KTEXT_BASE directly and failed immediately:
 *
 *     copyout failed at 0x0 -- resume there
 *
 * That is the very first read, and it is the whole answer. Every earlier
 * read that succeeded on this console was in the DATA segment (kdata +
 * 0x2885d50 and up); kernel TEXT was never successfully read. 8.60
 * enforces XOM: kernel .text is execute-only through its normal virtual
 * mapping. That is not an obstacle to work around -- it is precisely why
 * Byepervisor exists, since defeating XOM is what clearing NP_ENABLE
 * across the hypervisor VMCBs achieves.
 *
 * But XOM guards the virtual mapping, not physical memory. kstuff-lite
 * reads and writes kernel code through the direct map for exactly this
 * reason, walking the page tables and then accessing the physical address
 * via the physmap:
 *
 *     pmap = vmspace->vm_pmap
 *     dmap = pmap->pm_pml4 - pmap->pm_cr3      // phys 0 maps here
 *     pml  = pmap->pm_cr3                       // root PML4, physical
 *     phys = virt2phys(vaddr, dmap, pml)
 *     read via kernel_copyout(dmap + phys, ...)
 *
 * The page walk only reads PTE bytes out of page-table pages, which are
 * ordinary data pages and are not XOM protected, so it works even though
 * the target mapping is execute-only.
 *
 * Struct offsets below are the SDK's values for the 8.x branch
 * (crt/kernel.c, case 0x08600000), which is where 8.60 lands:
 *   KERNEL_OFFSET_PROC_P_VMSPACE = 0x200
 *   KERNEL_OFFSET_VMSPACE_VM_PMAP = 0x2e8
 *
 * STILL READ-ONLY with respect to the kernel: the only writes this
 * payload performs are to files under /data.
 *
 * Resumable and paced. See the file-writing section for the checkpoint
 * behaviour; a power cycle costs at most one chunk.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

#include "util.h"

#ifndef DUMP_CHUNK
#define DUMP_CHUNK 0x1000
#endif
#ifndef DUMP_DELAY_US
#define DUMP_DELAY_US 200000
#endif
#ifndef DUMP_MAX_READS
#define DUMP_MAX_READS 24
#endif

#define KTEXT_BASE 0xFFFFFFFF81000000ULL
#define KTEXT_SIZE 0xC70000ULL

#define OUT_PATH    "/data/bye860_ktext.bin"
#define RESUME_PATH "/data/bye860_resume.txt"

/* SDK values for the 8.x branch. */
#define OFF_PROC_P_VMSPACE   0x200
#define OFF_VMSPACE_VM_PMAP  0x2E8
#define PMAP_PML4_OFF        0x20
#define PMAP_CR3_OFF         0x28

#define PG_FRAME 0x000FFFFFFFFFF000ULL
#define X86_PG_V 0x001ULL
#define X86_PG_PS 0x080ULL

static uint64_t hex2ull(const char *s)
{
  uint64_t v = 0;
  if (!s)
    return 0;
  while (*s) {
    int d;
    if (*s >= '0' && *s <= '9')      d = *s - '0';
    else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
    else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
    else break;
    v = (v << 4) | (uint64_t)d;
    s++;
  }
  return v;
}

static uint64_t load_resume(void)
{
  FILE *f = fopen(RESUME_PATH, "r");
  char buf[64] = {0};
  uint64_t v;

  if (!f)
    return 0;
  if (!fgets(buf, sizeof buf, f)) {
    fclose(f);
    return 0;
  }
  fclose(f);

  v = hex2ull(buf);
  if (v > KTEXT_SIZE)
    return 0;
  return v;
}

static void save_resume(uint64_t off)
{
  FILE *f = fopen(RESUME_PATH, "w");
  if (!f)
    return;
  fprintf(f, "%llx\n", (unsigned long long)off);
  fflush(f);
  fclose(f);
}

/* Walk the page tables to translate a kernel virtual address to physical.
 * Mirrors ps5-kstuff's virt2phys. Returns (uint64_t)-1 on a missing
 * entry. On success phys_limit, when non-NULL, receives the first address
 * beyond the mapping so a chunk can be clamped to it. */
static uint64_t virt2phys(uint64_t addr, uint64_t *phys_limit,
                          uint64_t dmap, uint64_t pml)
{
  int i;

  pml &= PG_FRAME;

  for (i = 39; i >= 12; i -= 9) {
    uint64_t index    = (addr >> i) & 0x1FFULL;
    uint64_t offseta  = index * sizeof(uint64_t);
    uint64_t entry;

    if (kernel_copyout(dmap + pml + offseta, &entry, sizeof entry) != 0)
      return (uint64_t)-1;

    pml = entry;
    if (!(pml & X86_PG_V))
      return (uint64_t)-1;

    if ((pml & X86_PG_PS) || i == 12) {
      pml &= (1ULL << 52) - (1ULL << i);
      pml |= addr & ((1ULL << i) - 1);
      if (phys_limit)
        *phys_limit = (pml | ((1ULL << i) - 1)) + 1;
      return pml;
    }
    pml &= PG_FRAME;
  }

  return (uint64_t)-1;
}

int main(void)
{
  static uint8_t buf[DUMP_CHUNK];
  uint64_t done, vaddr, want, phys, limit, proc, vmspace;
  uint64_t pm_pml4, pm_cr3, dmap, pml;
  size_t   rc;
  int      n = 0;

  printf("[dump] alive. dmap-mode, chunk=0x%x delay=%dus max=%d\n",
         (unsigned int)DUMP_CHUNK, (int)DUMP_DELAY_US, (int)DUMP_MAX_READS);
  fflush(stdout);

  /* Discover the direct map. proc 0's pmap carries the kernel's own root
   * table and the recursive index, which together define phys 0. */
  proc = kernel_get_proc(0);
  printf("[dump] proc(0)      = 0x%lx\n", (unsigned long)proc);
  if (!proc) {
    printf("[dump] cannot resolve proc 0\n");
    fflush(stdout);
    return 1;
  }

  if (kernel_copyout(proc + OFF_PROC_P_VMSPACE, &vmspace, sizeof vmspace)) {
    printf("[dump] cannot read vmspace\n");
    fflush(stdout);
    return 1;
  }
  /* The pmap struct sits EMBEDDED at vmspace + VM_PMAP; it is not reached
   * through a pointer stored at that offset. Reading it as a pointer
   * yields garbage and a non-canonical dmap (observed on console:
   * 0x4140b0074fe800). This mirrors the SDK's kernel_find_dmap_base(),
   * which reads vmspace + VM_PMAP + 0x20 / + 0x28 directly. */
  if (kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_PML4_OFF,
                     &pm_pml4, sizeof pm_pml4) ||
      kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + PMAP_CR3_OFF,
                     &pm_cr3, sizeof pm_cr3)) {
    printf("[dump] cannot read pmap root pointers at vmspace+0x%x\n",
           (unsigned int)(OFF_VMSPACE_VM_PMAP + PMAP_PML4_OFF));
    fflush(stdout);
    return 1;
  }

  /* Prefer the SDK's value, which __kernel_init() already derived with
   * the correct walk, and keep ours as a cross-check. */
  dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
  pml  = pm_cr3;

  printf("[dump] pm_pml4      = 0x%lx\n", (unsigned long)pm_pml4);
  printf("[dump] pm_cr3       = 0x%lx\n", (unsigned long)pm_cr3);
  printf("[dump] pml4 - cr3   = 0x%lx (computed)\n",
         (unsigned long)(pm_pml4 - pm_cr3));
  printf("[dump] dmap (SDK)   = 0x%lx\n", (unsigned long)dmap);
  fflush(stdout);

  if (dmap != (pm_pml4 - pm_cr3)) {
    printf("[dump] note: computed and SDK dmap differ; using the SDK value.\n");
    printf("[dump] that implies VM_PMAP is not 0x%x on this build.\n",
           (unsigned int)OFF_VMSPACE_VM_PMAP);
    fflush(stdout);
  }

  if (!dmap || (dmap >> 48) != 0xFFFFULL) {
    printf("[dump] dmap is not a plausible canonical address; aborting\n");
    fflush(stdout);
    notifyf("[8.60 dump] FAILED\ndmap=0x%lx implausible", (unsigned long)dmap);
    return 1;
  }

  /* Sanity-check the walk on the first page of kernel text before
   * writing anything. */
  phys  = virt2phys(KTEXT_BASE, &limit, dmap, pml);
  printf("[dump] ktext[0] -> phys 0x%lx (mapping ends 0x%lx)\n",
         (unsigned long)phys, (unsigned long)limit);
  fflush(stdout);

  if (phys == (uint64_t)-1) {
    printf("[dump] page walk failed for ktext base; aborting before any write\n");
    fflush(stdout);
    notifyf("[8.60 dump] FAILED\npage walk failed\nno file written");
    return 1;
  }

  done = load_resume();
  printf("[dump] resuming at 0x%llx (%.2f%%)\n", (unsigned long long)done,
         100.0 * (double)done / (double)KTEXT_SIZE);
  fflush(stdout);

  if (done >= KTEXT_SIZE) {
    printf("[dump] already complete\n");
    fflush(stdout);
    notifyf("[8.60 dump]\ncomplete");
    return 0;
  }

  {
    FILE *out = fopen(OUT_PATH, done ? "r+b" : "wb");
    if (!out) {
      printf("[dump] cannot open %s\n", OUT_PATH);
      fflush(stdout);
      return 1;
    }
    if (done && fseek(out, (long)done, SEEK_SET) != 0) {
      printf("[dump] cannot seek to 0x%llx; delete %s and %s to restart\n",
             (unsigned long long)done, OUT_PATH, RESUME_PATH);
      fclose(out);
      return 1;
    }

    while (done < KTEXT_SIZE && n < DUMP_MAX_READS) {
      vaddr = KTEXT_BASE + done;
      want  = KTEXT_SIZE - done;
      if (want > (uint64_t)DUMP_CHUNK)
        want = (uint64_t)DUMP_CHUNK;

      usleep(DUMP_DELAY_US);

      limit = 0;
      phys  = virt2phys(vaddr, &limit, dmap, pml);
      if (phys == (uint64_t)-1) {
        printf("[dump] unmapped at offset 0x%llx (vaddr 0x%lx); stopping\n",
               (unsigned long long)done, (unsigned long)vaddr);
        fflush(out);
        fclose(out);
        save_resume(done);
        notifyf("[8.60 dump] unmapped\nat offset 0x%llx", (unsigned long long)done);
        return 2;
      }

      /* Never read past the end of the mapping that backs this chunk. */
      if (limit && (phys + want) > limit)
        want = limit - phys;
      if (!want) {
        printf("[dump] zero-length mapping at 0x%llx\n", (unsigned long long)done);
        fclose(out);
        save_resume(done);
        return 2;
      }

      rc = (size_t)kernel_copyout(dmap + phys, buf, (size_t)want);
      if (rc != want) {
        printf("[dump] copyout failed at offset 0x%llx (phys 0x%lx, rc %zu)\n",
               (unsigned long long)done, (unsigned long)phys, rc);
        fflush(out);
        fclose(out);
        save_resume(done);
        notifyf("[8.60 dump] copyout failed\nat 0x%llx", (unsigned long long)done);
        return 3;
      }

      if (fwrite(buf, 1, want, out) != want) {
        printf("[dump] short write at 0x%llx\n", (unsigned long long)done);
        fflush(out);
        fclose(out);
        save_resume(done);
        return 4;
      }

      fflush(out);
      fsync(fileno(out));

      done += want;
      save_resume(done);
      n++;

      printf("[dump] +%llu -> 0x%llx (%.2f%%)\n",
             (unsigned long long)want, (unsigned long long)done,
             100.0 * (double)done / (double)KTEXT_SIZE);
      fflush(stdout);
    }

    fflush(out);
    fclose(out);
  }

  if (done >= KTEXT_SIZE) {
    printf("[dump] COMPLETE: %llu bytes in %s\n",
           (unsigned long long)KTEXT_SIZE, OUT_PATH);
    fflush(stdout);
    notifyf("[8.60 dump] COMPLETE\n%llu bytes", (unsigned long long)KTEXT_SIZE);
    return 0;
  }

  printf("[dump] %d reads this run, at 0x%llx. Rerun to resume.\n",
         n, (unsigned long long)done);
  fflush(stdout);
  notifyf("[8.60 dump] %.1f%%\nrerun to resume",
          100.0 * (double)done / (double)KTEXT_SIZE);
  return 0;
}

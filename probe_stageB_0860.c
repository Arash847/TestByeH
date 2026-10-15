/* 8.60 stage-B diagnostic: find the readable ceiling of kernel data space.
 *
 * WHY THIS SHAPE
 * --------------
 * The stage-A probe proved the exploit supplies a sane, canonical
 * DATA_BASE with K = 0xC70000, so "the base was wrong" is RULED OUT as
 * the cause of the hard power-off. The remaining suspect is the range of
 * kernel addresses being read.
 *
 * The SDK's own kernel_find_iommu_softc() walks DOWNWARD from
 * KERNEL_ADDRESS_ALLPROC to DATA_BASE + 8 and aborts on the first failed
 * copyout. Because __kernel_init() requires that walk to succeed, the
 * entire range
 *
 *     [ DATA_BASE + 8 , DATA_BASE + KSTUFF_0860_ALLPROC ]
 *     = [ DATA_BASE + 8 , DATA_BASE + 0x2875D50 ]
 *
 * is PROVEN READABLE on every boot. Everything above 0x2875D50 is
 * unproven, and every 8.60 anchor this port needs (IDT 0x2EB3DF0, GDT
 * 0x2EB50D0, TSS 0x2EB6AD0, PCPU 0x2EC8A00, PMAP 0x2E48848) lies ABOVE
 * that ceiling. The previous probe read all of them back to back with no
 * checkpointing, so it could not report which one was fatal.
 *
 * A bad address here does not fail gracefully. kernel_copyout()
 * programs the socket to copy from kaddr and then reads from the pipe, so
 * an unmapped kaddr faults inside a kernel socket write path. That is a
 * kernel-context fault with no recoverable handler: the console
 * hard-powers-off and no output is produced.
 *
 * So this probe does three things the old one did not:
 *
 *   1. It reads ONE qword at a time, ascending from the proven-safe
 *      ceiling, instead of 355 blind reads.
 *   2. It prints and flushes the address, then WAITS, before each read.
 *      If the console dies, the last logged SCAN line names the exact
 *      address that killed it. The delay guarantees the line has reached
 *      the host before the fault.
 *   3. It checks kernel_copyout()'s return value and stops cleanly on a
 *      graceful failure, so a soft failure never escalates.
 *
 * A run that completes identifies the safe ceiling. A run that dies
 * identifies the first bad page. Both are progress; neither is a guess.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

#include "util.h"

#define KSTUFF_0860_ALLPROC    0x2875D50
#define KSTUFF_0860_PMAP_STORE 0x2E48848
#define KSTUFF_0860_IDT        0x2EB3DF0
#define KSTUFF_0860_GDT        0x2EB50D0
#define KSTUFF_0860_TSS_ARRAY  0x2EB6AD0
#define KSTUFF_0860_PCPU_ARRAY 0x2EC8A00

/* Settle time between logging an address and reading it. Long enough that
 * the line is delivered before a fault can hide it. */
#define SETTLE_US  700000
#define STEP       0x1000
#define SCAN_TOP   0x2F00000

int main(void)
{
  uint64_t dbase, k, off, addr, v = 0;
  int rc;

  printf("[stageB] alive. one qword per read, ascending, logged before read.\n");
  fflush(stdout);

  dbase = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  k     = (uint64_t)KERNEL_ADDRESS_DATA_BASE - (uint64_t)KERNEL_ADDRESS_TEXT_BASE;

  printf("[stageB] DATA_BASE = 0x%lx  K = 0x%lx\n", (unsigned long)dbase,
         (unsigned long)k);
  printf("[stageB] starting at the SDK-proven safe ceiling 0x%lx\n",
         (unsigned long)(dbase + KSTUFF_0860_ALLPROC));
  printf("[stageB] anchors of interest (kdata-rel): pmap=0x%x idt=0x%x "
         "gdt=0x%x tss=0x%x pcpu=0x%x\n",
         (unsigned int)KSTUFF_0860_PMAP_STORE, (unsigned int)KSTUFF_0860_IDT,
         (unsigned int)KSTUFF_0860_GDT, (unsigned int)KSTUFF_0860_TSS_ARRAY,
         (unsigned int)KSTUFF_0860_PCPU_ARRAY);
  fflush(stdout);

  for (off = KSTUFF_0860_ALLPROC; off < SCAN_TOP; off += STEP) {
    addr = dbase + off;

    /* Log the intent BEFORE the read and give the host time to receive
     * it. If the console powers off on this read, this line is the
     * diagnosis. */
    printf("[stageB] SCAN off=0x%lx addr=0x%lx ... ",
           (unsigned long)off, (unsigned long)addr);
    fflush(stdout);
    usleep(SETTLE_US);

    v = 0;
    rc = kread(addr, &v, sizeof v);

    if (rc != 0) {
      printf("COPYOUT_FAILED rc=%d\n", (int)rc);
      fflush(stdout);
      printf("[stageB] first graceful failure at kdata offset 0x%lx; "
             "readable ceiling is below this.\n", (unsigned long)off);
      fflush(stdout);
      notifyf("[stage B] copyout failed\nat kdata+0x%lx", (unsigned long)off);
      return 2;
    }

    printf("ok v=0x%016lx\n", (unsigned long)v);
    fflush(stdout);
  }

  printf("[stageB] scan completed through kdata+0x%x with no failure.\n",
         (unsigned int)SCAN_TOP);
  fflush(stdout);
  notifyf("[stage B] scan complete\nreadable to kdata+0x%x", (unsigned int)SCAN_TOP);
  return 0;
}

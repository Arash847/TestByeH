/* 8.60 stage-A diagnostic: PRINT ONLY. Performs no kernel reads.
 *
 * WHY THIS EXISTS
 * ---------------
 * A previous revision of this probe derived kernel addresses from
 * KERNEL_ADDRESS_DATA_BASE and issued several hundred kernel_copyout()
 * calls. The console hard-powered-off when it ran.
 *
 * The mechanism is understood:
 *
 *   - KERNEL_ADDRESS_DATA_BASE is supplied by the EXPLOIT through the
 *     payload args, and the SDK validates it only for non-zero:
 *         KERNEL_ADDRESS_DATA_BASE = args->kdata_base_addr;
 *         if(!(KERNEL_ADDRESS_DATA_BASE = args->kdata_base_addr))
 *                 return -EFAULT;
 *
 *   - kernel_copyout() performs NO validation of the target address. The
 *     0xffff... high-bits sanity check in kernel_write() applies to the
 *     PIPE address, not to the address being read:
 *         buf.pbuf.kaddr = kaddr;                 <- unchecked
 *         __crt_syscall(SYS_read, rw_pipe[0], uaddr, len);
 *
 * So if the running exploit reports a wrong base, every derived address is
 * wild, the kernel faults in kernel context, and the console powers off
 * with no diagnostic. A hard power-off is the expected signature.
 *
 * This revision therefore calls NO kernel read primitive at all. It only
 * prints values that are already in userland, and judges them by pure
 * arithmetic. It cannot fault the kernel under any circumstances, which
 * makes it safe to run as the first step on any console.
 *
 * It answers one question: is the base the exploit supplied sane?
 */

#include <sys/types.h>
#include <stdio.h>
#include <ps5/kernel.h>

#include "util.h"

/* K per firmware branch, from ps5-payload-dev/sdk crt/kernel.c. */
static const struct { unsigned fw; unsigned k; const char *name; } known[] = {
  { 0x08000000, 0x0C50000, "7.x"  },
  { 0x08600000, 0x0C70000, "8.x"  },
  { 0x09000000, 0x0CA0000, "9.x"  },
  { 0x10000000, 0x0CC0000, "10.x" },
  { 0x11000000, 0x0D30000, "11.x" },
  { 0x12000000, 0x0D50000, "12.x" },
  { 0x13000000, 0x0CB0000, "13.0" },
  { 0x13600000, 0x0CC0000, "13.6" },
};

int main(void)
{
  uint64_t tbase, dbase, K;
  uint32_t fw;
  unsigned i;
  int k_known = 0, base_canonical = 0;

  printf("[stageA] alive. print-only, zero kernel reads.\n");
  fflush(stdout);

  fw    = kernel_get_fw_version();
  tbase = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  dbase = (uint64_t)KERNEL_ADDRESS_DATA_BASE;

  printf("[stageA] fw        = 0x%x (%u.%02u)\n",
         (unsigned int)fw, (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
  printf("[stageA] soc_id    = 0x%x\n", (unsigned int)sceKernelGetMainSocId());
  printf("[stageA] TEXT_BASE = 0x%lx\n", (unsigned long)tbase);
  printf("[stageA] DATA_BASE = 0x%lx\n", (unsigned long)dbase);
  printf("[stageA] did not perform any kernel read\n");

  if (dbase == 0) {
    printf("[stageA] VERDICT: DATA_BASE is ZERO -- the exploit did not supply one.\n");
    printf("[stageA] VERDICT: DO NOT run any kernel-reading payload yet.\n");
    fflush(stdout);
    notifyf("[stage A] FAILED\nDATA_BASE = 0\nno kernel reads performed");
    return 1;
  }

  K = (dbase > tbase) ? (dbase - tbase) : 0;
  printf("[stageA] K (derived) = 0x%lx\n", (unsigned long)K);

  /* Pure arithmetic on values already in userland. No memory access. */
  base_canonical = ((dbase >> 48) == 0xFFFFULL);
  printf("[stageA] DATA_BASE canonical (top16 == 0xffff): %s\n",
         base_canonical ? "yes" : "NO -- looks wrong");

  for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
    if ((fw & 0xFFFF0000u) == known[i].fw) {
      printf("[stageA] expected K for %s = 0x%x\n", known[i].name,
             (unsigned int)known[i].k);
      k_known = (K == known[i].k);
      printf("[stageA] derived K %s expected value\n",
             k_known ? "MATCHES" : "DOES NOT MATCH");
      break;
    }
  }
  if (!i)
    printf("[stageA] no expected-K entry for this fw in this probe\n");

  /* Show the addresses a reading probe WOULD use, without touching them. */
  printf("[stageA] would read (not performed):\n");
  printf("[stageA]   IDT        0x%lx\n",
         (unsigned long)(dbase + 0x2EB3DF0));
  printf("[stageA]   GDT        0x%lx\n",
         (unsigned long)(dbase + 0x2EB50D0));
  printf("[stageA]   TSS_ARRAY  0x%lx\n",
         (unsigned long)(dbase + 0x2EB6AD0));
  printf("[stageA]   ALLPROC    0x%lx\n",
         (unsigned long)(dbase + 0x2875D50));

  fflush(stdout);

  if (base_canonical && k_known)
    notifyf("[stage A] base OK\nfw=%x K=0x%lx\nno reads performed",
            (unsigned int)fw, (unsigned long)K);
  else
    notifyf("[stage A] BASE SUSPECT\nfw=%x\nDATA=0x%lx K=0x%lx",
            (unsigned int)fw, (unsigned long)dbase, (unsigned long)K);

  printf("[stageA] done. no kernel memory was read or written.\n");
  fflush(stdout);
  return 0;
}

/* 8.60 stage-B diagnostic: map the readable range of kernel data space.
 *
 * FAST + PERSISTENT. Every line goes to console storage via logf(), which
 * flushes to disk before the next read. That matters for two reasons:
 *
 *   - A NetCat GUI does not display the payload's stdout, so on-screen
 *     notifications were the only visibility. Now the log survives on the
 *     console and can be copied to USB or pulled over the network.
 *   - It brackets a hard power-off far better than the previous
 *     "log, then sleep 700ms" trick. The log line is durably on disk
 *     before the risky read happens, so if the console dies the last line
 *     on disk is the last thing that was known good. That also removes
 *     the 700ms per-read delay that made the scan take ~73 seconds; this
 *     one finishes in a couple of seconds.
 *
 * Ruled out by earlier evidence, for the record:
 *
 *   - "The exploit supplies a wrong kdata_base_addr" -- stage A reported
 *     a canonical DATA_BASE with derived K=0xc70000 matching the SDK's
 *     0x08600000 table entry.
 *   - "Reads above ALLPROC are unmapped" -- an earlier scan read well
 *     past kdata+0x2885d50 without dying.
 *
 * So the scan below is now a survey rather than a fault hunt. What it
 * still establishes is which 8.60 anchors are safe to use, and it prints
 * the live contents of each one so the kstuff-lite table can be checked
 * against hardware instead of being trusted.
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

#define STEP     0x1000
#define SCAN_TOP 0x2F00000

static uint64_t dbase;

static int
looks_like_kptr(uint64_t v)
{
  return ((v >> 48) == 0xFFFFULL) && (v != 0);
}

/* Read one qword. Returns 0 on success, nonzero on a graceful failure.
 * Never trusts the destination buffer unless the copyout reported
 * success. */
static int
rd(uint64_t kaddr, uint64_t *out)
{
  uint64_t v = 0;
  int rc = kread(kaddr, &v, sizeof v);
  if (rc != 0)
    return rc;
  *out = v;
  return 0;
}

int
main(void)
{
  uint64_t k, off, addr, v;
  int rc;

  logf("[stageB] alive. persistent log: %s\n", log_path());
  logf("[stageB] fw=0x%x soc=0x%x\n",
       (unsigned int)(kernel_get_fw_version() & 0xffffffffU),
       (unsigned int)sceKernelGetMainSocId());

  dbase = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  k     = dbase - (uint64_t)KERNEL_ADDRESS_TEXT_BASE;

  logf("[stageB] DATA_BASE=0x%lx K=0x%lx\n",
       (unsigned long)dbase, (unsigned long)k);

  /* ---- phase 1: readable-range survey, no delay ---- */
  logf("[stageB] --- phase 1: range survey ---\n");
  for (off = KSTUFF_0860_ALLPROC; off < SCAN_TOP; off += STEP) {
    addr = dbase + off;
    rc = rd(addr, &v);
    if (rc != 0) {
      logf("[stageB] FIRST-FAIL off=0x%lx addr=0x%lx rc=%d\n",
           (unsigned long)off, (unsigned long)addr, rc);
      break;
    }
    logf("[stageB] ok off=0x%lx v=0x%016lx\n", (unsigned long)off,
         (unsigned long)v);
  }

  /* ---- phase 2: validate each 8.60 anchor ---- */
  logf("[stageB] --- phase 2: anchor validation ---\n");

  {
    uint64_t a = dbase + KSTUFF_0860_ALLPROC;
    if (rd(a, &v) == 0)
      logf("[stageB] ALLPROC   kdata+0x%08x = 0x%016lx %s\n",
           (unsigned int)KSTUFF_0860_ALLPROC, (unsigned long)v,
           looks_like_kptr(v) ? "KERNEL PTR ok" : "NOT A KERNEL PTR");
    else
      logf("[stageB] ALLPROC read FAILED\n");
  }

  {
    uint64_t a = dbase + KSTUFF_0860_PMAP_STORE;
    if (rd(a, &v) == 0)
      logf("[stageB] PMAP_STORE kdata+0x%08x = 0x%016lx %s\n",
           (unsigned int)KSTUFF_0860_PMAP_STORE, (unsigned long)v,
           v ? "nonzero" : "ZERO -- kstuff anchor wrong");
    else
      logf("[stageB] PMAP_STORE read FAILED\n");
  }

  /* IDT: census the gates and report the count plus a sample handler. */
  {
    uint64_t a = dbase + KSTUFF_0860_IDT;
    uint64_t base = dbase - (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    int i, gates = 0, read_ok = 1;
    uint64_t sample = 0;

    for (i = 0; i < 256; i++) {
      uint64_t e;
      if (rd(a + (uint64_t)i * 16, &e) != 0) { read_ok = 0; break; }
      if (!e) continue;
      {
        uint16_t lo  = (uint16_t)(e & 0xFFFF);
        uint16_t sel = (uint16_t)((e >> 16) & 0xFFFF);
        uint64_t h   = e >> 32;
        if ((lo & 1) && (lo & 0xE00) && sel == 0x08 &&
            looks_like_kptr(h)) {
          gates++;
          if (!sample) sample = h;
        }
      }
    }
    if (!read_ok) {
      logf("[stageB] IDT read FAILED at gate %d\n", i);
    } else {
      logf("[stageB] IDT       kdata+0x%08x plausible gates=%d/256\n",
           (unsigned int)KSTUFF_0860_IDT, gates);
      logf("[stageB] IDT sample handler=0x%lx ktext_off=0x%lx\n",
           (unsigned long)sample, (unsigned long)(sample - base));
    }
  }

  {
    uint64_t a = dbase + KSTUFF_0860_PCPU_ARRAY;
    int i, ok = 0;
    for (i = 0; i < 16; i++) {
      if (rd(a + (uint64_t)i * 8, &v) != 0) break;
      if (looks_like_kptr(v)) ok++;
    }
    logf("[stageB] PCPU_ARRAY kdata+0x%08x ptrs=%d/16\n",
         (unsigned int)KSTUFF_0860_PCPU_ARRAY, ok);
  }

  {
    uint64_t a = dbase + KSTUFF_0860_TSS_ARRAY;
    if (rd(a, &v) == 0)
      logf("[stageB] TSS_ARRAY kdata+0x%08x first qword=0x%016lx %s\n",
           (unsigned int)KSTUFF_0860_TSS_ARRAY, (unsigned long)v,
           looks_like_kptr(v) ? "kernel ptr" : "not a kernel ptr");
    else
      logf("[stageB] TSS_ARRAY read FAILED\n");
  }

  /* Is kernel text readable? Pure content judgement: util.c kread()
   * discards nothing now, so a failed copyout is visible as rc. */
  {
    uint64_t t[2] = { 0, 0 };
    uint64_t tb = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    rc = kread(tb, t, sizeof t);
    if (rc != 0) {
      logf("[stageB] ktext copyout FAILED rc=%d -> text NOT readable\n", rc);
    } else {
      int z = (t[0] == 0 && t[1] == 0);
      int o = (t[0] == ~(uint64_t)0 && t[1] == ~(uint64_t)0);
      logf("[stageB] ktext first 16 bytes:");
      for (int i = 0; i < 16; i++)
        logf(" %02x", (unsigned int)((uint8_t *)t)[i]);
      logf("\n");
      logf("[stageB] ktext %s\n",
           (z || o) ? "reads uniformly -> NOT readable"
                    : "READABLE (mixed content)");
    }
  }

  logf("[stageB] DONE. no kernel memory was written.\n");

  notifyf("[stage B] done\nlog written to console\nsee byepervisor_0860.log");
  return 0;
}

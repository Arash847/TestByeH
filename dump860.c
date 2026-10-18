/* 8.60 kernel .text dumper -- resumable and paced.
 *
 * WHY THIS SHAPE
 * --------------
 * Custom kernel reads on this console have already proven workable: a
 * paced scan read successfully past kdata+0x2885d50. What killed the
 * console was issuing reads back to back with no checkpoint. So this
 * payload assumes it will be interrupted and is built to survive that:
 *
 *   - every chunk is written to console storage and fsync'd BEFORE the
 *     next read begins, so the file on disk is always a valid prefix
 *   - a resume offset is stored after each chunk, so a power cycle costs
 *     at most one chunk
 *   - reads are paced with a settle delay, matching the only pattern
 *     observed to survive
 *   - each run does a bounded number of reads and then exits cleanly, so
 *     the payload is never resident long enough to destabilise anything
 *
 * Re-run after each power cycle; it picks up where it left off.
 *
 * READ-ONLY with respect to the kernel. The only writes are to files
 * under /data.
 *
 * Compilation knobs (see the Makefile):
 *   DUMP_CHUNK     bytes per kernel read   (default 0x1000)
 *   DUMP_DELAY_US  settle before each read (default 200000 = 200ms)
 *   DUMP_MAX_READS reads per run           (default 24)
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
  if (v > KTEXT_SIZE) {
    printf("[dump] resume offset 0x%lx is past the end; starting over\n",
           (unsigned long)v);
    return 0;
  }
  return v;
}

static void save_resume(uint64_t off)
{
  FILE *f = fopen(RESUME_PATH, "w");
  if (!f) {
    printf("[dump] WARNING: cannot write %s\n", RESUME_PATH);
    return;
  }
  fprintf(f, "%llx\n", (unsigned long long)off);
  fflush(f);
  fclose(f);
}

int main(void)
{
  static uint8_t buf[DUMP_CHUNK];
  uint64_t done, addr, total;
  size_t   want;
  int      n = 0, rc;

  printf("[dump] alive. chunk=0x%x delay=%dus max_reads=%d\n",
         (unsigned int)DUMP_CHUNK, (int)DUMP_DELAY_US, (int)DUMP_MAX_READS);
  printf("[dump] target ktext 0x%lx .. 0x%lx (%llu bytes)\n",
         (unsigned long)KTEXT_BASE, (unsigned long)(KTEXT_BASE + KTEXT_SIZE),
         (unsigned long long)KTEXT_SIZE);
  fflush(stdout);

  done = load_resume();
  printf("[dump] resuming at offset 0x%llx (%.2f%% done)\n",
         (unsigned long long)done, 100.0 * (double)done / (double)KTEXT_SIZE);
  fflush(stdout);

  if (done >= KTEXT_SIZE) {
    printf("[dump] already complete. Nothing to do.\n");
    fflush(stdout);
    notifyf("[8.60 dump]\ncomplete\n%llu bytes in /data", (unsigned long long)KTEXT_SIZE);
    return 0;
  }

  /* "r+b" keeps prior contents and seeks to the resume point; "wb" starts
   * fresh. Either way the file is only ever extended, never truncated
   * mid-run, so a power-off leaves a valid prefix. */
  {
    FILE *out = fopen(OUT_PATH, done ? "r+b" : "wb");
    if (!out) {
      printf("[dump] cannot open %s for writing\n", OUT_PATH);
      fflush(stdout);
      notifyf("[8.60 dump] FAILED\ncannot write %s", OUT_PATH);
      return 1;
    }

    if (done && fseek(out, (long)done, SEEK_SET) != 0) {
      printf("[dump] cannot seek to 0x%llx; file may be shorter than the "
             "resume record. Delete %s and %s to restart.\n",
             (unsigned long long)done, OUT_PATH, RESUME_PATH);
      fclose(out);
      return 1;
    }

    while (done < KTEXT_SIZE && n < DUMP_MAX_READS) {
      want = (size_t)((KTEXT_SIZE - done) < (uint64_t)DUMP_CHUNK
                      ? (KTEXT_SIZE - done) : (uint64_t)DUMP_CHUNK);
      addr = KTEXT_BASE + done;

      /* Settle before the read. This is the one behaviour that has been
       * observed to keep repeated kernel reads stable. */
      usleep(DUMP_DELAY_US);

      rc = (int)kernel_copyout(addr, buf, want);
      if (rc != 0) {
        printf("[dump] copyout FAILED rc=%d at offset 0x%llx (addr 0x%lx); "
               "resume offset unchanged\n",
               rc, (unsigned long long)done, (unsigned long)addr);
        fflush(out);
        fclose(out);
        save_resume(done);
        notifyf("[8.60 dump] copyout failed\nat 0x%llx -- resume there",
                (unsigned long long)done);
        return 2;
      }

      if (fwrite(buf, 1, want, out) != want) {
        printf("[dump] short write at offset 0x%llx\n", (unsigned long long)done);
        fflush(out);
        fclose(out);
        save_resume(done);
        return 3;
      }

      /* Durable BEFORE the next read, so an abrupt power-off cannot lose
       * a chunk that we already counted. */
      fflush(out);
      fsync(fileno(out));

      done += want;
      save_resume(done);
      n++;

      total = done;
      printf("[dump] +%zu -> 0x%llx  (%.2f%%)\n", want,
             (unsigned long long)total,
             100.0 * (double)total / (double)KTEXT_SIZE);
      fflush(stdout);
    }

    fflush(out);
    fclose(out);
  }

  printf("[dump] run finished: %d reads this run, offset 0x%llx\n",
         n, (unsigned long long)done);
  if (done >= KTEXT_SIZE) {
    printf("[dump] COMPLETE: %llu bytes in %s\n",
           (unsigned long long)KTEXT_SIZE, OUT_PATH);
    fflush(stdout);
    notifyf("[8.60 dump] COMPLETE\n%llu bytes -> bye860_ktext.bin",
            (unsigned long long)KTEXT_SIZE);
    return 0;
  }

  printf("[dump] incomplete. Power-cycle and re-run to resume from 0x%llx.\n",
         (unsigned long long)done);
  fflush(stdout);
  notifyf("[8.60 dump] %d reads done\n%.1f%% -- rerun to resume",
          n, 100.0 * (double)done / (double)KTEXT_SIZE);
  return 0;
}

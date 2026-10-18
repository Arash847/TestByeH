# Byepervisor Reborn — 8.60 port (slim / regular)

Work-in-progress port of
[EchoStretch/Byepervisor-Reborn](https://github.com/EchoStretch/Byepervisor-Reborn)
(`768e8a1`, the 12.xx–13.xx build with auto rest mode) to firmware **8.60**
on a **slim / regular-model** console.

Base note: this started life on the gzimbric 11.60 fork, but EchoStretch's
tree is the better base — newer, covers 12.xx–13.xx properly, and has the
auto rest-mode behaviour. The port was rebased onto it.

## Status: NOT runnable on 8.60

The 8.60 offset table is incomplete and the payload **refuses to run**
until it is finished. Nothing in this repo should be loaded on 8.60 yet.

| Component | State |
|---|---|
| Structural port (firmware dispatch, fail-closed guard) | done |
| 8.60 data symbols (IDT / TSS / pmap) | derived, formula-proven |
| 8.60 text symbols (4 data + 5 text + 15 of 21 gadgets) | **missing** |

## Why this matters for your console

Upstream's unsupported-firmware path was missing a `return 1`:

```c
if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Undetected firmware, exiting!\n");
    notifyf("[ERROR] ...Firmware is not supported :(\n");
}                       /* no return -- falls through */
```

So on an unsupported firmware it warned and then **ran the exploit anyway**
with a NULL hook target, entered rest mode, and hard power-offed the
console — which is the exact failure the upstream README describes for a
failed exploit. That is what happens on 8.60 with an unmodified build.

Fixed here, and CI (`audit` job) fails the build if the `return` is ever
removed again.

## What is established for 8.60

```text
ktext base   = 0xFFFFFFFF81000000
kdata base   = 0xFFFFFFFF81C70000
K            = 0xC70000
```

`K` was confirmed on hardware by a read-only probe (`fw=0x08600004`, derived
`K=0xc70000`, canonical base) and independently matches
`ps5-payload-dev/sdk` `crt/kernel.c` `case 0x08600000`. The SDK firmware
table and kstuff-lite agree exactly on all four branches they share
(8.x, 9.x, 11.x, 13.60).

Conversion, validated against the hardware-validated 11.60 table where all
three shared symbols reproduce exactly:

```text
ktext_offset = K + signed_kdata_offset

0xD30000 + 0x2E70300 = 0x3BA0300  = IDT_ARRAY
0xD30000 + 0x2E72FE0 = 0x3BA2FE0  = COMMON_TSS
0xD30000 + 0x2E04F18 = 0x3B34F18  = PMAP_STORE
```

Applied to 8.60:

| Symbol | ktext offset |
|---|---|
| `KERNEL_SYM_PMAP_STORE` | `0x3AB8848` |
| `KERNEL_SYM_IDT_ARRAY` | `0x3B23DF0` |
| `KERNEL_SYM_COMMON_TSS` | `0x3B26AD0` |

## What is still missing

Four data symbols (`DMPML4I`, `DMPDPI`, `PML4PML4I`, `DATA_CAVE`), all five
text symbols (`SYS_GETUID`, `PRINTF`, `ACPI_SLEEP_MACHDEP_HOOK`,
`HV_MP_STARTUP_CALL`, `MP_STARTUP_INIT_VECTOR`), and 15 of 21 gadgets.

No public 8.60 source provides these. Deriving them needs a trusted 8.60
kernel `.text` image. Do not copy them from 12.x/13.x — every firmware
build relocates every function, and a wrong offset here writes kernel
memory and redirects IDT/IST gates on all 16 cores.

Two things to expect once offsets exist, per the porting guide:

- 8.60 is assumed to lack a usable `pop r8`, so the chain should use the
  portable `pop rcx / pop rax / mov [rcx],rax` store
- the 13.x hypervisor heap/PCPU globals read as zero in the startup AP
  window on 11.60, so 8.60 should use runtime VMCB discovery rather than
  the fixed globals

## Getting a dump

See [`docs/PROSPER0GDB.md`](docs/PROSPER0GDB.md). Network tooling lives in
`scan-ports.ps1`, `r0gdb-dump.ps1` and `send-capture.ps1`.

Note: prosper0gdb needs `-DDEBUG` to bring its stub up, and the stub only
services packets from inside a trap. `-DINTERRUPTER_THREAD` was tried and
**regressed startup** — the stub port stopped opening entirely.

## Credits

- [EchoStretch/Byepervisor-Reborn](https://github.com/EchoStretch/Byepervisor-Reborn) — base
- [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) — 8.x anchors
- [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) — original
- [gzimbric/Byepervisor-Reborn](https://github.com/gzimbric/Byepervisor-Reborn) — 11.60 port, prior base
- [gzimbric/ps5-hv-bypass-porting](https://github.com/gzimbric/ps5-hv-bypass-porting) — workflow

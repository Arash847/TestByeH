# Getting an 8.60 kernel text dump via prosper0gdb

This is the supported way to obtain the 8.60 kernel image needed to finish
the offset table. It replaces the custom read probes, which repeatedly
power-off the console: `kernel_copyout()` is a `setsockopt` + blocking pipe
`read` through the socket-overlap primitive, and issuing those back to back
appears to corrupt the kernel socket path.

prosper0gdb does **not** do that. It reuses the loader's existing kernel
pipe and speaks the r0gdb protocol, which is what the porting guide names
as the required tool for bounded kernel observation:

> a way to observe bounded kernel control flow, normally r0gdb lineage
> — `docs/bootstrap-without-readable-kernel-text.md`

8.60 is supported natively and selected at runtime from
`prosper0gdb/offsets.c`:

```c
uint32_t ver = r0gdb_get_fw_version() >> 16;
case 0x860: set_offsets_860(); break;
```

No compile-time firmware selector is needed.

## Coordinates for 8.60

```text
ktext base = 0xFFFFFFFF81000000
kdata base = 0xFFFFFFFF81C70000
K          = 0xC70000
```

`K = 0xC70000` was confirmed on hardware by the stage-A probe
(`fw=0x8600004`, derived `K=0xc70000`) and independently matches
`ps5-payload-dev/sdk` `crt/kernel.c` `case 0x08600000`.

## Build

Requires host `gcc`, `yasm`, `python3`, and the payload SDK. The build
order below is taken from the repository's own `ci-ps5-kstuff-ldr.sh`.

```sh
sudo apt-get install build-essential yasm python3

wget -q https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
sudo unzip -q -o ps5-payload-sdk.zip -d /opt
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk

git clone https://github.com/EchoStretch/kstuff-lite
cd kstuff-lite
git submodule update --init --recursive

make -C ps5-kstuff
make -C ps5-kstuff-ldr
```

Output: `ps5-kstuff-ldr/kstuff.elf`

Note `lib` and `prosper0gdb` are built as dependencies of those targets;
run `make -C lib && make -C prosper0gdb` first if you hit a missing
`lib-elf-ps5.a`.

## Load and attach

`kstuff.elf` bundles the prosper0gdb stub. Send it to elfldr as usual:

```sh
nc -q0 $PS5_HOST 9021 < kstuff.elf
```

The stub then binds to the **first free port at or above 1234** and blocks
in `accept()`:

```c
for (int port = 1234; port < 65536 && brv; port++)
  ...
listen(sock, 1);
gdb_socket = accept(sock, NULL, NULL);
```

It binds `INADDR_ANY`, so from your build machine:

```sh
gdb-multiarch
(gdb) set architecture i386:x86-64
(gdb) target remote $PS5_HOST:1234
```

If 1234 does not answer, the stub took 1235 or later — check the console
notifications or try the next port.

## Sanity-check the anchors live

These validate the kstuff-lite 8.x table against hardware rather than
trusting it. `x/` is read-only.

```text
ALLPROC    kdata+0x2875D50  = 0xFFFFFFFF844E5D50
PMAP_STORE kdata+0x2E48848  = 0xFFFFFFFF84AB8848
IDT        kdata+0x2EB3DF0  = 0xFFFFFFFF84B23DF0
GDT        kdata+0x2EB50D0  = 0xFFFFFFFF84B250D0
TSS_ARRAY  kdata+0x2EB6AD0  = 0xFFFFFFFF84B26AD0
PCPU_ARRAY kdata+0x2EC8A00  = 0xFFFFFFFF84B38A00
```

```gdb
(gdb) x/8gx 0xFFFFFFFF84B23DF0        # IDT gates: handler>>32 in ktext, sel 0x08
(gdb) x/1gx  0xFFFFFFFF84AB8848       # pmap store: expect nonzero
(gdb) x/2gx  0xFFFFFFFF844E5D50       # allproc head: expect a 0xFFFF... ptr
```

## Dump the kernel text

```gdb
(gdb) dump binary memory ktext-8.60.bin 0xFFFFFFFF81000000 0xFFFFFFFF81C70000
```

That is 12.44 MB, covering the whole text region. Then validate locally:

```sh
python3 tools/validate_image.py ktext-8.60.bin --expected-size 0xC70000
```

## Read-only discipline

r0gdb is a full ring-0 debugger and can trivially brick the console with a
stray write. For this task only reads are needed:

- use `x/` to inspect, never `set {` or `write`
- use `dump binary memory` for extraction, not `restore`
- do not single-step or continue execution

## What this unblocks

With the text dump and `K = 0xC70000`, every remaining 8.60 value can be
derived offline with the porting-guide tools, with no further hardware
access:

- 5 text symbols: `SYS_GETUID`, `PRINTF`, `ACPI_SLEEP_MACHDEP_HOOK`,
  `HV_MP_STARTUP_CALL`, `MP_STARTUP_INIT_VECTOR`
- 4 data symbols: `DMPML4I`, `DMPDPI`, `PML4PML4I`, `DATA_CAVE`
- 15 of 21 gadgets

Already derived and formula-proven, recorded in `include/offsets/8_60.h`:

```text
KERNEL_SYM_IDT_ARRAY   0x3B23DF0
KERNEL_SYM_COMMON_TSS  0x3B26AD0
KERNEL_SYM_PMAP_STORE  0x3AB8848
```

The table stays fail-closed until the full production chain is validated.

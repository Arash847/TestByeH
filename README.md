# Byepervisor Reborn — 8.60 port (slim / regular model)

Work-in-progress port of [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn)
to firmware **8.60** on a **slim (regular-model)** console, based on the
11.60 fork [gzimbric/Byepervisor-Reborn](https://github.com/gzimbric/Byepervisor-Reborn).

## Status: NOT runnable on 8.60

The 8.60 offset table is intentionally empty and the build **refuses to
emit a chain** while it is unvalidated. There is no supported 8.60 exploit
here yet. The one thing this tree can actually do today is build and run a
read-only diagnostic.

| Component | State |
|---|---|
| Structural port (firmware dispatch, VMCB routing, fail-closed guard) | done |
| 8.60 offset table | **empty — blocking** |
| Read-only stage-0 probe | buildable, unvalidated on hardware |

## Why the table is empty

Every firmware build relocates every kernel function, so 8.60 symbol and
gadget offsets are not derivable from 11.60 or 13.60. A wrong offset here
does not fail gracefully: the payload writes kernel memory, redirects
IDT/IST gates on all 16 cores, and clears `NP_ENABLE` across hypervisor
VMCBs during S3 resume. A plausible-looking wrong value means a hung or
bricked console with no useful diagnostic.

`kdlsym.c` therefore returns NULL for 8.60 until
`G_SYM_MAP_0860_READY` and `G_GADGET_MAP_0860_READY` are both set, which
`main.c` already treats as "unsupported firmware".

## What is known for 8.60

Target model is slim/regular, so `HV_LOADER_PA_REGULAR = 0x062800000`.
The PS5 Pro path is refused until its physical layout is surveyed.

kstuff-lite provides a kdata-relative 8.x anchor table (shared across the
8.00/8.20/8.40/8.60 kernel branch). The conversion to Byepervisor's
ktext-relative form was verified against the hardware-validated 11.60
tables, where three independent symbols all yield `K = 0xD30000`:

```text
ktext_offset = K + signed_kdata_offset
K = kdata_base - ktext_base
```

`K` is not interpolable and must be measured on 8.60:

```text
K(9.60)  = 0xCA0000
K(13.60) = 0xCC0000
K(11.60) = 0xD30000
```

## Stage 0: the diagnostic

`probe_0860.c` measures `K` from two fully independent anchors — the CPU
IDT and GDT descriptor-table registers — because two independent anchors
must agree before any offset is believed:

```text
K_idt = (IDTR.base - ktext_base) - 0x2EB3DF0
K_gdt = (GDTR.base - ktext_base) - 0x2EB50D0
```

It then validates the result independently by walking all 256 IDT gates
for present/64-bit/selector-`0x08` entries whose handlers point back into
kernel text, and reports whether kernel text is readable.

8.60 predates enforced XOM, so readable ktext is expected. If so, a text
dump plus `K` is sufficient to derive the remaining 9 symbols and 15
gadgets offline with the
[porting guide](https://github.com/gzimbric/ps5-hv-bypass-porting) tools.

The probe is **read-only**: it writes nothing to kernel memory, installs
no gate, touches no IST entry, does not enter rest mode, and does not
access hypervisor physical memory.

## Build

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make probe-0860    # byepervisor_probe_0860.elf
```

Send `byepervisor_probe_0860.elf` through
[elfldr](https://github.com/ps5-payload-dev/elfldr). GitHub Actions builds
this on every push.

## Credits

- [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) — base exploit
- [gzimbric/Byepervisor-Reborn](https://github.com/gzimbric/Byepervisor-Reborn) — 11.60 fork, starting point
- [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) — 8.x anchor table
- [gzimbric/ps5-hv-bypass-porting](https://github.com/gzimbric/ps5-hv-bypass-porting) — porting workflow

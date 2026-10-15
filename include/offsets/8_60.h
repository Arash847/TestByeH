#ifndef OFFSETS_8_60_H
#define OFFSETS_8_60_H

/* ===================================================================
 * 8.60 offset table -- UNVALIDATED SCAFFOLD
 * ===================================================================
 *
 * STATUS: every entry below is 0. This table is intentionally empty.
 *
 * Do NOT fill these in by copying 11.60 or 13.60 values. Every firmware
 * build relocates every kernel function; a neighbouring table's offsets
 * are not a starting guess, they are simply wrong numbers that will
 * point into unrelated kernel text with convincing low bits.
 *
 * A wrong offset in this project does not fail gracefully. The payload
 * writes into kernel memory, redirects IDT/IST gates on all 16 cores,
 * and clears NP_ENABLE across hypervisor VMCBs during S3 resume. A
 * plausible-looking wrong offset here means a hung or bricked console
 * with no useful diagnostic on the way there.
 *
 * TO COMPLETE THIS TABLE you need, in this order:
 *
 *   1. DONE. K = kdata_base - ktext_base = 0xC70000 for 8.60, confirmed
 *      on hardware by the stage-A probe (reported fw=0x8600004, derived
 *      K=0xc70000, matching the SDK's 0x08600000 table entry).
 *   2. A trusted 8.60 kernel .text image, and ideally an hvcore
 *      image. Validate the image first (tools/validate_image.py) and
 *      cross-check one structure against hardware.
 *   3. Candidate discovery with the porting-guide offline tools,
 *      then confirmation against live anchors on the console.
 *
 * Derivation commands (from the porting guide):
 *
 *   python3 -I tools/find_symbols.py ktext IMAGE --k 0x<K>
 *   python3 -I tools/find_symbols.py hvcore IMAGE --base 0x<BASE>
 *   python3 tools/find_bytes.py IMAGE "55 48 ?? e5"
 *   python3 tools/disassemble.py IMAGE OFFSET LENGTH --base VA
 *   python3 tools/find_rel32.py IMAGE TARGET --limit END
 *
 * Every value must be recorded with its basis (ktext/kdata/physical/
 * structure) and the evidence that promoted it from candidate to
 * accepted. See firmwares/8.60.json.
 *
 * Assumptions carried over from 11.60. 8.60 is older, so these are
 * working hypotheses to be MEASURED, not facts:
 *
 *   - 11.60 has no usable `pop r8` in kernel .text and the chain uses
 *     the portable `pop rcx / pop rax / mov [rcx],rax` store instead.
 *     8.60 is assumed no better; confirm by search before relying on it.
 *   - The 13.x hypervisor heap and PCPU globals read as zero inside the
 *     startup AP window on 11.60. 8.60 is assumed the same, hence the
 *     zero entries below and the runtime VMCB discovery path.
 * =================================================================== */

/* ===================================================================
 * Public data-side anchors for 8.60 (from kstuff-lite 8_60.h)
 * ===================================================================
 * kstuff-lite expresses every offset as KDATA-relative; negative values
 * sign-extend backwards into kernel text. Byepervisor needs ktext-
 * relative values, so the conversion is:
 *
 *     ktext_offset = K + signed_kdata_offset
 *     where K = kdata_base - ktext_base
 *
 * The conversion was verified against the hardware-validated 11.60
 * tables, where three independent symbols all yield K = 0xD30000:
 *
 *     IDT_ARRAY  0x3BA0300 - 0x2E70300 = 0xD30000
 *     COMMON_TSS 0x3BA2FE0 - 0x2E72FE0 = 0xD30000
 *     PMAP_STORE 0x3B34F18 - 0x2E04F18 = 0xD30000
 *
 * K is NOT interpolable across firmware and must not be guessed:
 *
 *     K(9.60)  = 0xCA0000
 *     K(13.60) = 0xCC0000
 *     K(11.60) = 0xD30000
 *
 * Non-monotonic. A borrowed K yields offsets whose low bits look
 * plausible while pointing into unrelated code. Measure it on 8.60.
 *
 * NOTE: kstuff-lite shares one table across the 8.00/8.20/8.40/8.60
 * kernel branch, so these anchors are branch-level values, not
 * per-build. Confirm at least two on the console before trusting them.
 * =================================================================== */
#define KSTUFF_0860_IDT               0x2EB3DF0   /* kdata-rel */
#define KSTUFF_0860_TSS_ARRAY         0x2EB6AD0   /* kdata-rel */
#define KSTUFF_0860_KERNEL_PMAP_STORE 0x2E48848   /* kdata-rel */
#define KSTUFF_0860_PCPU_ARRAY        0x2EC8A00   /* kdata-rel */
#define KSTUFF_0860_ALLPROC           0x2875D50   /* kdata-rel */

/* Text-side (kstuff-lite kdata-rel, negative) -> ktext-rel via the same K.
 * These are LEADS for the resume path, not accepted gadgets. Each must be
 * disassembled and confirmed by execution before use. */
#define KSTUFF_0860_DORETI_IRET       (-0xA27973) /* candidate IRETQ */
#define KSTUFF_0860_ADD_RSP_IRET      (-0xA2797A) /* candidate pivot   */
#define KSTUFF_0860_REP_MOVSB_POP_RBP (-0x9EB2C6) /* candidate REP_MOVSB */
#define KSTUFF_0860_STORE_RAX_RDI     (-0xA2EE6E) /* candidate store    */
#define KSTUFF_0860_DR2GPR_START      (-0xA2EA93) /* candidate DR path  */
#define KSTUFF_0860_GPR2DR_1_START    (-0xA2E97A) /* candidate DR path  */
#define KSTUFF_0860_SWAPGS_ADD_RSP_IRET (-0xA27979)

/* K for 8.60 is now ESTABLISHED, from two independent public sources that
 * agree exactly on every firmware branch:
 *
 *   ps5-payload-dev/sdk  crt/kernel.c, case 0x08600000:
 *       KERNEL_ADDRESS_TEXT_BASE = KERNEL_ADDRESS_DATA_BASE - 0x0C70000
 *       KERNEL_ADDRESS_ALLPROC   = KERNEL_ADDRESS_DATA_BASE + 0x2875D50
 *
 *   kstuff-lite 8_60.h: allproc = 0x2875D50
 *
 * The SDK's firmware table and kstuff-lite's anchors agree EXACTLY on all
 * four branches that both cover, which confirms kstuff's table is
 * kdata-relative and correctly transcribed:
 *
 *   FW      SDK ALLPROC   kstuff allproc   match
 *   8.x     +0x2875D50    0x2875D50        exact
 *   9.x     +0x2755D50    0x2755D50        exact
 *   11.x    +0x2875D70    0x2875D70        exact
 *   13.60   +0x28C9E80    0x28C9E80        exact
 *
 * CAUTION: KERNEL_ADDRESS_DATA_BASE is supplied by the EXPLOIT via
 * payload args and the SDK checks it only for non-zero. If the running
 * exploit reports a wrong base, every derived address is wild, and
 * kernel_copyout() performs NO validation on the target address -- the
 * kernel faults in kernel context and the console hard-powers-off. Any
 * 8.60 diagnostic must sanity-check DATA_BASE before dereferencing it
 * and must propagate kernel_copyout()'s return value.
 */
#define KDATA_KTEXT_GAP_0860          0x0C70000   /* CONFIRMED, two sources */

/* ---- kernel symbols (ktext-relative unless noted) ------------------ */
uint64_t g_sym_map_0860[] = {
  0,          // KERNEL_SYM_DMPML4I                 basis kdata, NOT IN KSTUFF
  0,          // KERNEL_SYM_DMPDPI                  basis kdata, NOT IN KSTUFF
  0,          // KERNEL_SYM_PML4PML4I               basis kdata, NOT IN KSTUFF
  0,          // KERNEL_SYM_SYS_GETUID              basis ktext, NOT IN KSTUFF
  0,          // KERNEL_SYM_PRINTF                  basis ktext, NOT IN KSTUFF
  0,          // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK basis ktext, NOT IN KSTUFF
  0,          // KERNEL_SYM_HV_MP_STARTUP_CALL      basis ktext, NOT IN KSTUFF
  0,          // KERNEL_SYM_MP_STARTUP_INIT_VECTOR  basis ktext, NOT IN KSTUFF
  0x3AB8848,  // KERNEL_SYM_PMAP_STORE   ktext-rel, DERIVED + FORMULA-PROVEN
  0,          // KERNEL_SYM_DATA_CAVE               basis kdata, NOT IN KSTUFF
  0x3B23DF0,  // KERNEL_SYM_IDT_ARRAY   ktext-rel, DERIVED + FORMULA-PROVEN
  0x3B26AD0,  // KERNEL_SYM_COMMON_TSS  ktext-rel, DERIVED + FORMULA-PROVEN
  0,          // HV_SYM_HEAP_BASE    -- 0 = use runtime VMCB discovery
  0,          // HV_SYM_PCPUS        -- 0 = use runtime VMCB discovery
};

/* ---- gadgets (ktext-relative) -------------------------------------- */
/* 0 means "not validated for 8.60". See the fail-closed guard in
 * kdlsym.c, which refuses to build a chain while entries are 0. */
uint64_t g_gadget_map_0860[] = {
  0,          // KERNEL_GADGET_PIVOT_ADD_RSP28_RET  add rsp,0x28 ; ret
  0,          // KERNEL_GADGET_IRETQ                iretq
  0,          // KERNEL_GADGET_POP_RAX              pop rax ; ret
  0,          // KERNEL_GADGET_POP_RCX              pop rcx ; ret
  0,          // KERNEL_GADGET_POP_RDI              pop rdi ; ret
  0,          // KERNEL_GADGET_POP_RSI              pop rsi ; ret
  0,          // KERNEL_GADGET_POP_RDX              pop rdx ; ret
  0,          // KERNEL_GADGET_POP_R8   -- assume absent; portable store
  0,          // KERNEL_GADGET_POP_RSP              pop rsp ; ret
  0,          // KERNEL_GADGET_STORE_RCX_R8          unused by portable store
  0,          // KERNEL_GADGET_STORE_RDI8_RCX
  0,          // KERNEL_GADGET_OR_RCX_EAX
  0,          // KERNEL_GADGET_SET_DR7
  0,          // KERNEL_GADGET_ST_RCX_RDX
  0,          // KERNEL_GADGET_ST_RCX_RAX           portable store target
  0,          // KERNEL_GADGET_MOV_RAX_RSI
  0,          // KERNEL_GADGET_MOV_RAX_RDI
  0,          // KERNEL_GADGET_REP_MOVSB
  0,          // KERNEL_GADGET_CLD
  0,          // KERNEL_GADGET_RET_TRAMP
  0,          // KERNEL_GADGET_DBREG_RESUME
};

/* Coverage summary from the public 8.60 sources (kstuff-lite 8_60.h):
 *
 *   data-side symbols resolved via public table : 3 of 7
 *     PMAP_STORE, IDT_ARRAY, COMMON_TSS   (all still need K)
 *   data-side symbols absent from it        : DMPML4I, DMPDPI,
 *                                            PML4PML4I, DATA_CAVE
 *   text-side symbols absent from it        : all 5
 *                                            SYS_GETUID, PRINTF,
 *                                            ACPI_SLEEP_MACHDEP_HOOK,
 *                                            HV_MP_STARTUP_CALL,
 *                                            MP_STARTUP_INIT_VECTOR
 *   gadget leads present (unconfirmed)      : 6 of 21
 *
 * So the public table resolves the data side but does NOT finish the
 * port. The text-side symbols and the majority of gadgets still require
 * either a kernel .text image or blind-bootstrap execution evidence.
 */

/* Set to 1 once every entry required by the production chain has been
 * derived AND validated on hardware. The guard in kdlsym.c refuses to
 * emit a chain while this is 0, so an incomplete table cannot be run by
 * accident. */
#define G_SYM_MAP_0860_READY  0
#define G_GADGET_MAP_0860_READY 0

#endif // OFFSETS_8_60_H

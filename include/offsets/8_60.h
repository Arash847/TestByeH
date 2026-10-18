#ifndef OFFSETS_8_60_H
#define OFFSETS_8_60_H

/* ===================================================================
 * 8.60 offsets for Byepervisor Reborn (EchoStretch base).
 *
 * Target: slim / regular-model console, firmware 8.60
 * (observed kernel_get_fw_version() == 0x08600004).
 *
 * STATUS: data side derived and formula-proven; text side still EMPTY.
 * This table is deliberately incomplete and the payload refuses to run
 * until it is finished. See G_*_READY below.
 *
 * -------------------------------------------------------------------
 * Coordinate conversion
 * -------------------------------------------------------------------
 * Byepervisor stores every value ktext-relative. kstuff-lite stores its
 * values kdata-relative, with negatives sign-extending back into text.
 * The conversion is
 *
 *     ktext_offset = K + signed_kdata_offset
 *     K            = kdata_base - ktext_base
 *
 * K for 8.60 is 0xC70000. It was confirmed on hardware by a read-only
 * stage-A probe, which reported the canonical SDK data base with a
 * derived K of 0xc70000, and it independently matches
 * ps5-payload-dev/sdk crt/kernel.c:
 *
 *     case 0x08600000:
 *       KERNEL_ADDRESS_TEXT_BASE = KERNEL_ADDRESS_DATA_BASE - 0x0C70000
 *
 * The formula itself was validated on the hardware-validated 11.60
 * table, where all three shared symbols reproduce exactly:
 *
 *     0xD30000 + 0x2E70300 = 0x3BA0300  = IDT_ARRAY
 *     0xD30000 + 0x2E72FE0 = 0x3BA2FE0  = COMMON_TSS
 *     0xD30000 + 0x2E04F18 = 0x3B34F18  = PMAP_STORE
 *
 * kstuff-lite's table shares one entry set across the 8.00/8.20/8.40/
 * 8.60 kernel branch, and its ALLPROC (0x2875D50) matches the SDK's
 * 8.x ALLPROC exactly, which is what confirms the anchors are correctly
 * transcribed.
 *
 * -------------------------------------------------------------------
 * WHAT IS STILL MISSING
 * -------------------------------------------------------------------
 * Four data symbols (DMPML4I, DMPDPI, PML4PML4I, DATA_CAVE), all five
 * text symbols, and 15 of 21 gadgets are not available from any public
 * 8.60 source. Deriving them needs a trusted 8.60 kernel .text image.
 *
 * Until then this port cannot run on 8.60, and says so instead of
 * entering rest mode with a NULL hook target, which is what hard
 * power-offs an unsupported console.
 *
 * The porting guide also notes two things to expect once offsets exist:
 *   - 8.60 is assumed to lack a usable `pop r8`, so the chain should use
 *     the portable `pop rcx / pop rax / mov [rcx],rax` store instead.
 *     Confirm by search before relying on it.
 *   - the 13.x hypervisor heap/PCPU globals read as zero inside the
 *     startup AP window on 11.60. 8.60 is assumed the same, hence the
 *     zero entries below; runtime VMCB discovery should be used.
 * =================================================================== */

/* kstuff-lite 8_60.h anchors, kdata-relative. The SDK's firmware table
 * and kstuff-lite agree exactly on all four branches they share (8.x,
 * 9.x, 11.x, 13.60), which is what makes these usable as candidates. */
#define KSTUFF_0860_ALLPROC    0x2875D50
#define KSTUFF_0860_PCPU_ARRAY 0x2EC8A00
#define KSTUFF_0860_PMAP_STORE 0x2E48848
#define KSTUFF_0860_IDT        0x2EB3DF0
#define KSTUFF_0860_GDT        0x2EB50D0
#define KSTUFF_0860_TSS_ARRAY  0x2EB6AD0

#define KDATA_KTEXT_GAP_0860   0x0C70000  /* CONFIRMED two ways */

/* ---- kernel symbols, ktext-relative -------------------------------- */
uint64_t g_sym_map_0860[] = {
  0,          // KERNEL_SYM_DMPML4I                 no public 8.60 source
  0,          // KERNEL_SYM_DMPDPI                  no public 8.60 source
  0,          // KERNEL_SYM_PML4PML4I               no public 8.60 source
  0,          // KERNEL_SYM_SYS_GETUID              no public 8.60 source
  0,          // KERNEL_SYM_PRINTF                  no public 8.60 source
  0,          // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK no public 8.60 source
  0,          // KERNEL_SYM_HV_MP_STARTUP_CALL      no public 8.60 source
  0,          // KERNEL_SYM_MP_STARTUP_INIT_VECTOR  no public 8.60 source
  0x3AB8848,  // KERNEL_SYM_PMAP_STORE   K + kstuff kernel_pmap_store
  0,          // KERNEL_SYM_DATA_CAVE               no public 8.60 source
  0x3B23DF0,  // KERNEL_SYM_IDT_ARRAY   K + kstuff idt
  0x3B26AD0,  // KERNEL_SYM_COMMON_TSS  K + kstuff tss_array
  0,          // HV_SYM_HEAP_BASE    -- 0 = use runtime VMCB discovery
  0,          // HV_SYM_PCPUS        -- 0 = use runtime VMCB discovery
};

/* ---- gadgets, ktext-relative --------------------------------------- */
/* 0 means "not derived for 8.60". Do NOT copy these from 12.x/13.x.
 * Every firmware build relocates every function; a borrowed offset is
 * simply wrong, and here a wrong offset means a hung or bricked console
 * with no diagnostic. */
uint64_t g_gadget_map_0860[] = {
  0,          // KERNEL_GADGET_PIVOT_ADD_RSP28_RET
  0,          // KERNEL_GADGET_IRETQ
  0,          // KERNEL_GADGET_POP_RAX
  0,          // KERNEL_GADGET_POP_RCX
  0,          // KERNEL_GADGET_POP_RDI
  0,          // KERNEL_GADGET_POP_RSI
  0,          // KERNEL_GADGET_POP_RDX
  0,          // KERNEL_GADGET_POP_R8      assumed absent on 8.60
  0,          // KERNEL_GADGET_POP_RSP
  0,          // KERNEL_GADGET_STORE_RCX_R8 unused by the portable store
  0,          // KERNEL_GADGET_STORE_RDI8_RCX
  0,          // KERNEL_GADGET_OR_RCX_EAX
  0,          // KERNEL_GADGET_SET_DR7
  0,          // KERNEL_GADGET_ST_RCX_RDX
  0,          // KERNEL_GADGET_ST_RCX_RAX  portable store target
  0,          // KERNEL_GADGET_MOV_RAX_RSI
  0,          // KERNEL_GADGET_MOV_RAX_RDI
  0,          // KERNEL_GADGET_REP_MOVSB
  0,          // KERNEL_GADGET_CLD
  0,          // KERNEL_GADGET_RET_TRAMP
  0,          // KERNEL_GADGET_DBREG_RESUME
};

/* Set to 1 only once the table is complete AND hardware validated. The
 * guard in kdlsym.c refuses to hand out addresses while this is 0, so an
 * incomplete table cannot be run by accident. */
#define G_SYM_MAP_0860_READY    0
#define G_GADGET_MAP_0860_READY 0

#endif // OFFSETS_8_60_H

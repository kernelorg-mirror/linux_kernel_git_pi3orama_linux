#ifndef _PERF_DWARF_REGS_H_
#define _PERF_DWARF_REGS_H_

#ifdef HAVE_DWARF_SUPPORT
const char *get_arch_regstr(unsigned int n);
#endif

#ifdef HAVE_BPF_PROLOGUE
/*
 * Arch should support fetching the offset of a register in pt_regs
 * by its name.
 */
int arch_get_reg_info(const char *name, int *offset);
#endif
#endif

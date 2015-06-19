/*
 * dwarf-regs.c : Mapping of DWARF debug register numbers into register names.
 * Extracted from probe-finder.c
 *
 * Written by Masami Hiramatsu <mhiramat@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <stddef.h>
#include <dwarf-regs.h>
#include <string.h>
#include <linux/ptrace.h>
#include <linux/kernel.h> /* for offsetof */
#include <util/bpf-loader.h>

struct reg_info {
	const char	*name;		/* Reg string in debuginfo      */
	int		offset;		/* Reg offset in struct pt_regs */
};

/*
 * Generic dwarf analysis helpers
 */
/*
 * x86_64 compiling can't access pt_regs for x86_32, so fill offset
 * with -1.
 */
#ifdef __x86_64__
# define REG_INFO(n, f) { .name = n, .offset = -1, }
#else
# define REG_INFO(n, f) { .name = n, .offset = offsetof(struct pt_regs, f), }
#endif
#define X86_32_MAX_REGS 8

struct reg_info x86_32_regs_table[X86_32_MAX_REGS] = {
	REG_INFO("%ax", eax),
	REG_INFO("%cx", ecx),
	REG_INFO("%dx", edx),
	REG_INFO("%bx", ebx),
	REG_INFO("$stack", esp),	/* Stack address instead of %sp */
	REG_INFO("%bp", ebp),
	REG_INFO("%si", esi),
	REG_INFO("%di", edi),
};

#undef REG_INFO
#ifdef __x86_64__
# define REG_INFO(n, f) { .name = n, .offset = offsetof(struct pt_regs, f), }
#else
# define REG_INFO(n, f) { .name = n, .offset = -1, }
#endif
#define X86_64_MAX_REGS 16
struct reg_info x86_64_regs_table[X86_64_MAX_REGS] = {
	REG_INFO("%ax",		rax),
	REG_INFO("%dx",		rdx),
	REG_INFO("%cx",		rcx),
	REG_INFO("%bx",		rbx),
	REG_INFO("%si",		rsi),
	REG_INFO("%di",		rdi),
	REG_INFO("%bp",		rbp),
	REG_INFO("%sp",		rsp),
	REG_INFO("%r8",		r8),
	REG_INFO("%r9",		r9),
	REG_INFO("%r10",	r10),
	REG_INFO("%r11",	r11),
	REG_INFO("%r12",	r12),
	REG_INFO("%r13",	r13),
	REG_INFO("%r14",	r14),
	REG_INFO("%r15",	r15),
};

#ifdef __x86_64__
#define ARCH_MAX_REGS X86_64_MAX_REGS
#define arch_regs_table x86_64_regs_table
#else
#define ARCH_MAX_REGS X86_32_MAX_REGS
#define arch_regs_table x86_32_regs_table
#endif

/* Return architecture dependent register string (for kprobe-tracer) */
const char *get_arch_regstr(unsigned int n)
{
	return (n <= ARCH_MAX_REGS) ? arch_regs_table[n].name : NULL;
}

#ifdef HAVE_BPF_PROLOGUE
int arch_get_reg_info(const char *name, int *offset)
{
	int i;
	struct reg_info *info;

	if (!name || !offset)
		return -1;

	for (i = 0; i < ARCH_MAX_REGS; i++) {
		info = &arch_regs_table[i];
		if (strcmp(info->name, name) == 0) {
			if (info->offset < 0)
				return -1;
			*offset = info->offset;
			return 0;
		}
	}

	return -1;
}
#endif

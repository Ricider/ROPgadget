## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import re
from   capstone import *
from capstone.x86 import *
#from .x86_const import *

class Gadgets(object):
    def __init__(self, binary, options, offset):
        self.__binary  = binary
        self.__options = options
        self.__offset  = offset
        self.__arch = self.__binary.getArch()

        re_str = ""
        if self.__arch == CS_ARCH_X86:
            re_str = "db|int3"
        elif self.__arch == CS_ARCH_ARM64:
            re_str = "brk|smc|hvc"
        if self.__options.filter:
            if re_str:
                re_str += "|"
            re_str += self.__options.filter

        self.__filterRE = re.compile("({})$".format(re_str)) if re_str else None

    def __passCleanX86(self, decodes):
        br = ["ret", "retf", "int", "sysenter", "jmp", "call", "syscall","jge","je","jle","ja","jb","jne","jz","jnz"]

        if decodes[-1][2] not in br:
            return True
        if not self.__options.multibr and any(mnemonic in br for _, _, mnemonic, _ in decodes[:-1]):
            return True
        if any("ret" in mnemonic for _, _, mnemonic, _ in decodes[:-1]):
            return True

        return False

    def __findSetters(self, gadget, idx, targetReg):
        if idx >= len(gadget):
            return []
        
        setters = []
        #print('findSetters idx=%i, len(gadget)=%i' % (idx, len(gadget)))
        for i in range(idx, len(gadget)):
            insn = gadget[i]
            if len(insn.operands) == 0: # Need this to prevent double-free errors...
                continue
            #self.__printInsn('in setter', insn)
            #print('numOps=%i' % len(insn.operands))
            
            # Check if this instruction writes to the target register
            (regsRead, regsWritten) = insn.regs_access() # Causes double free error when ud0 instruction encountered
            #for r in regsWritten:
            #    print("reg read: %s" % insn.reg_name(r))
            if targetReg in regsWritten:
                setters.append((insn, i))
        return setters

    def __printInsn(self, key, insn):
        print("(%s): 0x%x:\t%s\t%s" % (key, insn.address, insn.mnemonic, insn.op_str))

    def __isLoader(self, insn):
        return insn.id == X86_INS_POP or (insn.id == X86_INS_MOV and insn.operands[1].type == X86_OP_MEM) 

    #def __isConveyor(insn):
    #    return insn.id == X86_INS_POP or insn.id == X86_INS_MOV

    # Finds all instructions that load a value to the target register
    def __findLoaders(self, gadget, idx, targetReg):
        if idx >= len(gadget):
            return []
        
        loaders = []
        setters = self.__findSetters(gadget, idx, targetReg) # Tuples of (insn, idx) pair
        for (setter, i) in setters:
            if self.__isLoader(setter):
                loaders.append((setter, i))
            #elif self.__isConveyor(insn):
            #    for op in setter.operands: # Find a loader for either operand
            #        if op.type == X86_OP_REG:
            #            loaders += self.__findLoaders(gadget, i, op.reg)
        return loaders

    # If this instruction reads and writes to this register
    def __isIterator(self, insn, reg):
        if len(insn.operands) == 0:
            return False

        if insn.id == X86_INS_POP:
            #self.__printInsn('iter', insn)
            return True
        elif insn.id == X86_INS_ADD or insn.id == X86_INS_SUB: 
            if len(insn.operands) >= 2:
                op2 = insn.operands[1]
                # I don't understand this condition; why not check if it reads the register (added here, but not in original)
                if not (op2.type == X86_OP_MEM and op2.mem.base == reg) and (reg in insn.regs_read):
                    #self.__printInsn('iter', insn)
                    return True
        elif insn.id == X86_INS_LEA:
            op1 = insn.operands[1]
            if op1.type == X86_OP_MEM and (op1.mem.base == reg or op1.mem.index == reg):
                self.__printInsn('iter', insn)
                return True
        
        return False

    #def __findIterators(gadget, idx, targetReg):
    #    if idx >= len(gadget):
    #        return []
    #    
    #    iterators = []
    #    setters = self.__findSetters(gadget, idx, targetReg)
    #    for (setter, i) in setters:
    #        if self.__isIterator(setter, targetReg):
    #            iterators.append((setter, i))
    #        elif self.__isConveyor(insn):
    #            for op in setter.operands: # Find an iterator for either operand
    #                if op.type == X86_OP_REG:
    #                    iterators += self.__findIterators(gadget, i, op.reg)
    #    return iterators

    def __hasIterator(self, gadget, idx, targetReg):
        if idx >= len(gadget):
            return False
       
        setters = self.__findSetters(gadget, idx, targetReg)
        #print('setters', setters)
        for (setter, i) in setters:
            if self.__isIterator(setter, targetReg):
                return True
            elif setter.id == X86_INS_MOV:
                op2 = setter.operands[1]
                lookupRegs = []
                if op2.type == X86_OP_REG:
                    lookupRegs.append(op2.reg)
                elif op2.type == X86_OP_MEM:
                    lookupRegs.append(op2.mem.base)
                    lookupRegs.append(op2.mem.index)

                for lookupReg in lookupRegs:
                    if self.__hasIterator(gadget, i+1, lookupReg):
                        return True
            #elif self.__isConveyor(insn):
            #    for op in setter.operands: # Find an iterator for either operand
            #        if op.type == X86_OP_REG and self.__hasIterator(gadget, i, op.reg):
            #            return True
        return False

    # Determines whether the gadget has an iterator and a loader (if register jump)
    def __isDispatcher(self, gadget):
        jmp = gadget[0]
        if len(jmp.operands) == 0 or len(gadget) <= 1: # direct jump
            #self.__printInsn('invalid', jmp)
            return False
        
        op1 = jmp.operands[0]
        if op1.type == X86_OP_REG: # Register jump
            
            jmpReg = op1.reg
            for (loader, i) in self.__findLoaders(gadget, 1, jmpReg):
                #print("(loader) 0x%x:\t%s\t%s" % (loader.address, loader.mnemonic, loader.op_str))
                if self.__isIterator(loader, jmpReg):
                    return True
                else: # Find an iterator for any of the loader's operands
                    for op in loader.operands:
                        if op.type == X86_OP_REG and self.__hasIterator(gadget, i+1, op.reg):
                            #if len(self.__findIterators(gadget, i, op.reg) > 0):
                            #self.__printInsn('loader', loader)
                            return True
        elif op1.type == X86_OP_MEM: # Memory-indirect jump
            #print('memory indirect gadget')
            #for i in reversed(gadget):
            #    self.__printInsn('gadget', i)
            #print('---')
            if self.__hasIterator(gadget, 1, op1.mem.base):
                return True
            if self.__hasIterator(gadget, 1, op1.mem.index):    
                return True
        
        return False

    def __getSysArgsWritten(self, gadget, numArgs):
        
        written = {}
        
        # rdi, rsi, rdx, r10, r8, r9
        sysRegs = [
            [X86_REG_RDI, X86_REG_EDI],
            [X86_REG_RSI, X86_REG_ESI],
            [X86_REG_RDX, X86_REG_EDX],
            [X86_REG_R10],
            [X86_REG_R8],
            [X86_REG_R9],
        ]
 
        if numArgs >= len(sysRegs):
            return written

        regRax = [X86_REG_RAX, X86_REG_EAX]    
        raxWritten = False 
        isSys = False
 
        for insn in gadget:
            #print("0x%x:\t%s\t%s (isSys=%s)" % (insn.address, insn.mnemonic, insn.op_str, 'syscall' in insn.mnemonic))
            if 'syscall' in insn.mnemonic: #insn.opcode == X86_INS_SYSCALL:
                #print("0x%x:\t%s\t%s (isSys=%s)" % (insn.address, insn.mnemonic, insn.op_str, insn.opcode==X86_INS_SYSCALL))
                isSys = True

            (regsRead, regsWritten) = insn.regs_access() # Causes double free error when ud0 instruction encountered
            
            # check if rax was written
            if not raxWritten:
                for reg in regRax:
                    if reg in regsWritten:
                        raxWritten = True
                        break
                
            for i in range(0, numArgs): # Checks if this instruction writes to any of the system call registers
                regs = sysRegs[i]
                for reg in regs:
                    if reg in regsWritten:
                        key = insn.reg_name(regs[0])
                        written[key] = True
                        break

        return (written, isSys, raxWritten)

    def __gadgetsFinding(self, section, gadgets, arch, mode, findDisp, sysargs, sysargsall):

        PREV_BYTES = 9 # Number of bytes prior to the gadget to store.

        opcodes = section["opcodes"]
        sec_vaddr = section["vaddr"]

        ret = []
        md = Cs(arch, mode)
        if findDisp:
            print('Finding dispatchers')
            md.detail = True

        # Filter gadgets to adhere to system call registers
        strictSysArgs = False # Must write to all required system registers
        numSysArgs = -1
        if sysargsall != -1: # set the stricter first if both are set by accident
            numSysArgs = sysargsall
            strictSysArgs = True
            md.detail = True
        else:
            if sysargs != -1:
                numSysArgs = sysargs
                md.detail = True
        print('numSysArgs=%i, strictSysArgs=%s' % (numSysArgs, strictSysArgs))

        for gad_op, gad_size, gad_align in gadgets:
            allRefRet = [m.start() for m in re.finditer(gad_op, opcodes)]
            for ref in allRefRet:
                end = ref + gad_size
                for i in range(self.__options.depth):
                    start = ref - (i * gad_align)
                    if (sec_vaddr+start) % gad_align == 0:
                        code = opcodes[start:end]
                        decodes = md.disasm_lite(code, sec_vaddr+ref)
                        decodes = list(decodes)
                        if sum(size for _, size, _, _ in decodes) != i*gad_align + gad_size:
                            # We've read less instructions than planned so something went wrong
                            continue
                        if self.passClean(decodes):
                            continue

                        writtenStr = ''
                        if findDisp or numSysArgs >= 0: 
                            g = md.disasm(code, sec_vaddr+ref)
                            g = list(g)
                            g.reverse()
                            if findDisp: # Check if this gadget is a dispatcher gadget
                                if not self.__isDispatcher(g):
                                    continue
                            if numSysArgs >= 0: # Filter out gadget if it does not adhere to system call register requirements
                                (written, isSys, raxWritten) = self.__getSysArgsWritten(g, numSysArgs)
                                print('%i regs written, isSys=%s, raxWritten=%s' % (len(written.keys()), isSys, raxWritten))
                                if isSys and not raxWritten: # rax must have a depth of zero in syscall gadgets
                                    continue

                                if strictSysArgs:
                                    if len(written.keys()) < numSysArgs:
                                        continue
                                else:
                                    if len(written.keys()) == 0:
                                        continue
                            
                                writtenStr = writtenStr + ('Regs written: ')    
                                for reg in written.keys():
                                    writtenStr = writtenStr + reg + ', '
                                if raxWritten:
                                    writtenStr = writtenStr + 'rax'  
 
                        off = self.__offset
                        vaddr = off+sec_vaddr+start
                        g = {"vaddr" :  vaddr}
                        if not self.__options.noinstr:
                            g["gadget"] = " ; ".join("{}{}{}".format(mnemonic, " " if op_str else "", op_str)
                                                     for _, _, mnemonic, op_str in decodes).replace("  ", " ")
                            if numSysArgs >= 0:
                                g["gadget"] = g["gadget"] + " ; " + writtenStr
                        if self.__options.callPreceded:
                            prevBytesAddr = max(sec_vaddr, vaddr - PREV_BYTES)
                            g["prev"] = opcodes[prevBytesAddr-sec_vaddr:vaddr-sec_vaddr]
                        if self.__options.dump:
                            g["bytes"] = code
                        ret.append(g)
        return ret

    def addROPGadgets(self, section, sysargs, sysargsall):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()

        if arch == CS_ARCH_X86:
            gadgets = [
                            [b"\xc3", 1, 1],                # ret
                            [b"\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
                            [b"\xcb", 1, 1],                # retf
                            [b"\xca[\x00-\xff]{2}", 3, 1],  # retf <imm>
                            # MPX
                            [b"\xf2\xc3", 2, 1],               # ret
                            [b"\xf2\xc2[\x00-\xff]{2}", 4, 1], # ret <imm>
                       ]

        elif arch == CS_ARCH_MIPS:   gadgets = []            # MIPS doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_PPC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x4e\x80\x00\x20", 4, 4] # blr
                          ]
            else:
                gadgets = [
                               [b"\x20\x00\x80\x4e", 4, 4] # blr
                          ]

        elif arch == CS_ARCH_SPARC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x81\xc3\xe0\x08", 4, 4], # retl
                               [b"\x81\xc7\xe0\x08", 4, 4], # ret
                               [b"\x81\xe8\x00\x00", 4, 4]  # restore
                          ]
            else:
                gadgets = [
                               [b"\x08\xe0\xc3\x81", 4, 4], # retl
                               [b"\x08\xe0\xc7\x81", 4, 4], # ret
                               [b"\x00\x00\xe8\x81", 4, 4]  # restore
                          ]
            arch_mode = 0

        elif arch == CS_ARCH_ARM:    gadgets = []            # ARM doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_ARM64:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\xd6\x5f\x03\xc0", 4, 4] # ret
                          ]
            else:
                gadgets = [
                               [b"\xc0\x03\x5f\xd6", 4, 4] # ret
                          ]
            arch_mode = CS_MODE_ARM

        else:
            print("Gadgets().addROPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian, False, sysargs, sysargsall)
        return gadgets


    def addBOPGadgets(self, section, findDisp, sysargs, sysargsall):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()
        if arch  == CS_ARCH_X86:
            gadgets = [
    
                [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1],     # jmp  [reg]
                [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1],     # jmp  [reg]
                [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call [reg]
                [b"\xeb[\x00-\xff]", 2, 1],                        # jmp offset
                [b"\xe9[\x00-\xff]{4}", 5, 1],                     # jmp offset
                # MPX
                [b"\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}", 3, 1],     # jmp  [reg]
                [b"\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 3, 1], # jmp  [reg]
                [b"\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}", 3, 1],     # jmp  [reg]
                [b"\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 3, 1],  # call [reg]            
                #conditional
                               [b"\x74[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x7f[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x7d[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x7e[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x76[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x72[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x73[\x00-\xff]{1}", 2, 1],                     # 1 byte
                               [b"\x77[\x00-\xff]{1}", 2, 1],                     # 1 byte
                      ]


        elif arch == CS_ARCH_MIPS: gadgets = []
        elif arch == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif arch == CS_ARCH_SPARC:  gadgets = []
        elif arch == CS_ARCH_ARM64: gadgets = []
        elif arch == CS_ARCH_ARM: gadgets = []
        else:
            print("Gadgets().addBOPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian, findDisp, sysargs, sysargsall)
        return gadgets

    def addJOPGadgets(self, section, findDisp, sysargs, sysargsall):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()



        if arch  == CS_ARCH_X86:
            gadgets = [
                               [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                               [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call [reg]
                               [b"\xeb[\x00-\xff]", 2, 1],                        # jmp offset
                               [b"\xe9[\x00-\xff]{4}", 5, 1],                     # jmp offset
                               # MPX
                               [b"\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 3, 1], # jmp  [reg]
                               [b"\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 3, 1]  # call [reg]
                      ]


        elif arch == CS_ARCH_MIPS:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x00[\x40\x60\x80\xa0\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4],               # jalr $v[0-1]|$a[0-3]
                               [b"[\x01\x02][\x00\x20\x40\x60\x80\xa0\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4], # jalr $t[0-7]|$s[0-7]
                               [b"\x03[\x00\x20\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4],                       # jalr $t[8-9]|$s8|$ra
                               [b"\x00[\x40\x60\x80\xa0\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4],               # jr $v[0-1]|$a[0-3]
                               [b"[\x01\x02][\x00\x20\x40\x60\x80\xa0\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4], # jr $t[0-7]|$s[0-7]
                               [b"\x03[\x00\x20\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4],                       # jr $t[8-9]|$s8|$ra
                               [b"[\x0c-\x0f][\x00-\xff]{7}", 8, 4],                                          # jal addr
                               [b"[\x08-\x0b][\x00-\xff]{7}", 8, 4]                                           # j addr
                          ]
            else:
                gadgets = [
                               [b"\x09\xf8[\x40\x60\x80\xa0\xc0\xe0]\x00[\x00-\xff]{4}", 8, 4],               # jalr $v[0-1]|$a[0-3]
                               [b"\x09\xf8[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x01\x02][\x00-\xff]{4}", 8, 4], # jalr $t[0-7]|$s[0-7]
                               [b"\x09\xf8[\x00\x20\xc0\xe0]\x03[\x00-\xff]{4}", 8, 4],                       # jalr $t[8-9]|$s8|$ra
                               [b"\x08\x00[\x40\x60\x80\xa0\xc0\xe0]\x00[\x00-\xff]{4}", 8, 4],               # jr $v[0-1]|$a[0-3]
                               [b"\x08\x00[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x01\x02][\x00-\xff]{4}", 8, 4], # jr $t[0-7]|$s[0-7]
                               [b"\x08\x00[\x00\x20\xc0\xe0]\x03[\x00-\xff]{4}", 8, 4],                       # jr $t[8-9]|$s8|$ra
                               [b"[\x00-\xff]{3}[\x0c-\x0f][\x00-\xff]{4}", 8, 4],                            # jal addr
                               [b"[\x00-\xff]{3}[\x08-\x0b][\x00-\xff]{4}", 8, 4]                             # j addr
                          ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif arch == CS_ARCH_SPARC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4]  # jmp %g[0-3]
                          ]
            else:
                gadgets = [
                               [b"\x00[\x00\x40\x80\xc0]{1}\xc0\x81", 4, 4]  # jmp %g[0-3]
                          ]
            arch_mode = 0
        elif arch == CS_ARCH_ARM64:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\xd6[\x1f\x5f]{1}[\x00-\x03]{1}[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}", 4, 4],  # br reg
                               [b"\xd6\?[\x00-\x03]{1}[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}", 4, 4]  # blr reg
                          ]
            else:
                gadgets = [
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}[\x1f\x5f]{1}\xd6", 4, 4],  # br reg
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}\?\xd6", 4, 4]  # blr reg
                          ]
            arch_mode = CS_MODE_ARM
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                if arch_endian == CS_MODE_BIG_ENDIAN:
                    gadgets = [
                               [b"\x47[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}", 2, 2], # bx   reg
                               [b"\x47[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}", 2, 2], # blx  reg
                               [b"\xbd[\x00-\xff]{1}", 2, 2]                                     # pop {,pc}
                              ]
                else:
                    gadgets = [
                               [b"[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                               [b"[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                               [b"[\x00-\xff]{1}\xbd", 2, 2]                                     # pop {,pc}
                              ]
                arch_mode = CS_MODE_THUMB
            else:
                if arch_endian == CS_MODE_BIG_ENDIAN:
                    gadgets = [
                               [b"\xe1\x2f\xff[\x10-\x19\x1e]{1}", 4, 4],  # bx   reg
                               [b"\xe1\x2f\xff[\x30-\x39\x3e]{1}", 4, 4],  # blx  reg
                               [b"[\xe8\xe9][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\x80-\xff][\x00-\xff]", 4, 4] # ldm {,pc}
                              ]
                else:
                    gadgets = [
                               [b"[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                               [b"[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                               [b"[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\xe8\xe9]", 4, 4] # ldm {,pc}
                              ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addJOPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian, findDisp, sysargs, sysargsall)
        return gadgets

    def addSYSGadgets(self, section, sysargs, sysargsall):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()

        if   arch == CS_ARCH_X86:
            gadgets = [
                               [b"\xcd\x80", 2, 1],                         # int 0x80
                               [b"\x0f\x34", 2, 1],                         # sysenter
                               [b"\x0f\x05", 2, 1],                         # syscall
                               [b"\x65\xff\x15\x10\x00\x00\x00", 7, 1],     # call DWORD PTR gs:0x10
                               [b"\xcd\x80\xc3", 3, 1],                     # int 0x80 ; ret
                               [b"\x0f\x34\xc3", 3, 1],                     # sysenter ; ret
                               [b"\x0f\x05\xc3", 3, 1],                     # syscall ; ret
                               [b"\x65\xff\x15\x10\x00\x00\x00\xc3", 8, 1], # call DWORD PTR gs:0x10 ; ret
                      ]

        elif arch == CS_ARCH_MIPS:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x00\x00\x00\x0c", 4, 4] # syscall
                          ]
            else:
                gadgets = [
                               [b"\x0c\x00\x00\x00", 4, 4] # syscall
                          ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # TODO (sc inst)
        elif arch == CS_ARCH_SPARC:  gadgets = [] # TODO (ta inst)
        elif arch == CS_ARCH_ARM64:  gadgets = [] # TODO
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"\x00-\xff]{1}\xef", 2, 2] # FIXME: svc
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"\x00-\xff]{3}\xef", 4, 4] # FIXME: svc
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addSYSGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian, False, sysargs, sysargsall)
        return []


    def passClean(self, decodes):

        if not decodes:
            return True

        if self.__arch == CS_ARCH_X86 and self.__passCleanX86(decodes):
            return True

        if self.__filterRE and any(self.__filterRE.match(mnemonic) for _, _, mnemonic, _ in decodes):
            return True

        return False


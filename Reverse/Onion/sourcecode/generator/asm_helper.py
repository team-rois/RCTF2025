import struct
MASK_32 = 0xFFFFFFFF
MASK_64 = 0xFFFFFFFFFFFFFFFF
INPUT_BUFFER_START = 0xE000
CODE_START_ADDR = 0x0200
# VM Memory map
SBOX_MEM_ADDR = 0x7000   # For RC4
KEY_MEM_ADDR = 0x7100    # For RC4
SPECK_KEY_MEM_ADDR = 0x7200 # 16 bytes for Speck key

class Assembler:
    """A simple assembler for custom VM."""
    
    def __init__(self):
        self.bytecode = bytearray()
        self.labels = {}
        self.fixups = []
        self.macro_counter = 0 

    def get_addr(self): return len(self.bytecode)
    def emit(self, *args): self.bytecode.extend(args)
    def emit_u16(self, val): self.bytecode.extend(struct.pack('<H', val))
    def emit_u32(self, val): self.bytecode.extend(struct.pack('<I', val))
    def emit_u64(self, val): self.bytecode.extend(struct.pack('<Q', val))
    def emit_raw(self, data): self.bytecode.extend(data)
    
    def label(self, name): 
        if name in self.labels:
            print(f"Warning: Label '{name}' already defined at {self.labels[name]:04X}, new: {self.get_addr():04X}")
        self.labels[name] = self.get_addr()
    
    def emit_fixup(self, label_name, size=2):
        if size != 2: raise ValueError("Only 16-bit fixups supported")
        self.fixups.append((self.get_addr(), label_name))
        self.emit(0xDE, 0xAD) # 16-bit placeholder

    def pad_to(self, addr):
        padding = addr - self.get_addr()
        if padding > 0: self.emit(*([0x00] * padding))

    # --- Opcodes ---
    def JMP(self, label):     self.emit(0x01); self.emit_fixup(label)
    def JNZ(self, label):     self.emit(0x02); self.emit_fixup(label)
    def JZ(self, label):      self.emit(0x03); self.emit_fixup(label)
    def LD_IX_IMM(self, val): self.emit(0x11); self.emit_u16(val)
    def LD_IY_IMM(self, val): self.emit(0x12); self.emit_u16(val)
    def LDQ_IX(self, reg):    self.emit(0x15, reg)
    def MOV_IMM64(self, reg, val): self.emit(0x16, reg); self.emit_u64(val)
    def MOV_REG(self, r_dst, r_src): self.emit(0x17, r_dst, r_src)
    def LDQ_IX_OFF(self, reg, off): self.emit(0x18, reg); self.emit_u16(off) 
    def STQ_IX(self, reg):    self.emit(0x19, reg)
    def LDB_IX_REG(self, r_dst, r_off): self.emit(0x1A, r_dst, r_off)
    def STB_IX_REG(self, r_src, r_off): self.emit(0x1B, r_src, r_off)
    def INC_REG(self, reg):   self.emit(0x1C, reg)
    def DEC_REG(self, reg):   self.emit(0x1D, reg)
    def SHR_IMM(self, reg, val): self.emit(0x1E, reg, val)
    def ADD_IX_REG(self, reg):self.emit(0x1F, reg)
    def AND_REG(self, r_dst, r_src): self.emit(0x25, r_dst, r_src)
    def XOR_REG(self, r_dst, r_src): self.emit(0x26, r_dst, r_src)
    def SHL_IMM(self, reg, val8):    self.emit(0x27, reg, val8)
    def XOR_IMM64(self, reg, val): self.emit(0x29, reg); self.emit_u64(val)
    def AND_IMM64(self, reg, val): self.emit(0x2A, reg); self.emit_u64(val)
    def LDB_IY_REG(self, r_dst, r_off): self.emit(0x2B, r_dst, r_off)
    def STB_IY_REG(self, r_src, r_off): self.emit(0x2C, r_src, r_off)
    def CMP_IMM64(self, reg, val): self.emit(0x32, reg); self.emit_u64(val)
    
    # --- System Opcodes ---
    def FUN_START(self):      self.emit(0x80)
    def FUN_END(self, id):    self.emit(0x81, id)
    def CALL_ID(self, id):    self.emit(0x82, id)
    def RET(self):            self.emit(0x83)
    def PUSH(self, reg):      self.emit(0x84, reg)
    def POP(self, reg):       self.emit(0x85, reg)
    def OUT_IMM(self, char):  self.emit(0x90, ord(char))
    def HALT(self):           self.emit(0xFF)
    def emit_string(self, s):
        for char in s: self.OUT_IMM(char)

    # --- ALU MACROS ---
    
    def LOGICAL_ADD_IMM(self, reg_a, val_b):
        """ Emits an inline logical-adder loop. (reg_a = reg_a + val_b) """
        REG_B = 6; REG_CARRY = 7
        loop_id = self.macro_counter; self.macro_counter += 1
        start_label = f"_add_imm_loop_start_{loop_id}"
        end_label = f"_add_imm_loop_end_{loop_id}"
        
        self.PUSH(REG_B); self.PUSH(REG_CARRY)
        self.MOV_IMM64(REG_B, val_b) 
        self.label(start_label)
        self.MOV_REG(REG_CARRY, reg_a); self.AND_REG(REG_CARRY, REG_B)
        self.XOR_REG(reg_a, REG_B); self.CMP_IMM64(REG_CARRY, 0) 
        self.JZ(end_label); self.SHL_IMM(REG_CARRY, 1)
        self.MOV_REG(REG_B, REG_CARRY); self.JMP(start_label)
        self.label(end_label)
        self.POP(REG_CARRY); self.POP(REG_B)

    def LOGICAL_ADD_REG(self, reg_dst, reg_src):
        """ Emits an inline logical-adder loop. (reg_dst = reg_dst + reg_src) """
        REG_B_TEMP = 6; REG_CARRY = 7
        loop_id = self.macro_counter; self.macro_counter += 1
        start_label = f"_add_reg_loop_start_{loop_id}"
        end_label = f"_add_reg_loop_end_{loop_id}"
        self.PUSH(REG_B_TEMP); self.PUSH(REG_CARRY)
        self.MOV_REG(REG_B_TEMP, reg_src)
        self.label(start_label)
        self.MOV_REG(REG_CARRY, reg_dst); self.AND_REG(REG_CARRY, REG_B_TEMP)
        self.XOR_REG(reg_dst, REG_B_TEMP); self.CMP_IMM64(REG_CARRY, 0) 
        self.JZ(end_label); self.SHL_IMM(REG_CARRY, 1)
        self.MOV_REG(REG_B_TEMP, REG_CARRY); self.JMP(start_label)
        self.label(end_label)
        self.AND_IMM64(reg_dst,MASK_64)
        self.POP(REG_CARRY); self.POP(REG_B_TEMP)

    def LOGICAL_SUB_IMM(self, reg_a, val_b):
        """ Emits an inline logical-sub loop. (reg_a = reg_a - val_b) """
        REG_B = 5
        self.PUSH(REG_B)
        self.MOV_IMM64(REG_B, val_b)
        self.XOR_IMM64(REG_B, 0xFFFFFFFFFFFFFFFF)
        self.LOGICAL_ADD_IMM(REG_B, 1)
        self.LOGICAL_ADD_REG(reg_a, REG_B)
        self.AND_IMM64(reg_a,MASK_64)
        self.POP(REG_B)
        
    def ROR32(self, reg, val):
        """ Emits 32-bit ROR logic. Clobbers R6, R7 """
        self.PUSH(6)
        self.PUSH(7)
        self.MOV_REG(6, reg)      # R6 = val
        self.MOV_REG(7, reg)      # R7 = val
        self.SHR_IMM(6, val)      # R6 = val >> r
        self.SHL_IMM(7, 32 - val) # R7 = val << (32-r)
        self.XOR_REG(6, 7)        # R6 = (val >> r) | (val << (32-r))
        self.AND_IMM64(6, MASK_32) # Mask to 32 bits
        self.POP(7)
        self.MOV_REG(reg, 6)
        self.POP(6)
        
    def ROL32(self, reg, val):
        """ Emits 32-bit ROL logic. Clobbers R6, R7 """
        self.PUSH(6)
        self.PUSH(7)
        self.MOV_REG(6, reg)      # R6 = val
        self.MOV_REG(7, reg)      # R7 = val
        self.SHL_IMM(6, val)      # R6 = val << r
        self.SHR_IMM(7, 32 - val) # R7 = val >> (32-r)
        self.XOR_REG(6, 7)        # R6 = (val << r) | (val >> (32-r))
        self.AND_IMM64(6, MASK_32) # Mask to 32 bits
        self.POP(7)
        self.MOV_REG(reg, 6)
        self.POP(6)

    def link(self):
        for addr, label_name in self.fixups:
            if label_name not in self.labels:
                raise ValueError(f"Undefined label: '{label_name}' at 0x{addr:04X}")
            target_addr = self.labels[label_name]
            packed_addr = struct.pack('<H', target_addr)
            self.bytecode[addr:addr+2] = packed_addr
    
    def get_bytecode(self):
        self.link()
        return self.bytecode

    def write_to_file(self, filename, link_before_write=True):
        if link_before_write:
            self.link()
        with open(filename, "wb") as f:
            f.write(self.bytecode)
        print(f"Wrote {len(self.bytecode)} bytes to '{filename}'.")

# --- Generator Helper Functions ---

def create_fail_func(asm):
    asm.FUN_START()
    asm.JMP("fail_body_end")
    asm.label("fail_body")
    asm.emit_string("Fail\n")
    asm.HALT()
    asm.RET() 
    asm.label("fail_body_end")
    asm.FUN_END(0x01)

def create_rc4_cipher_func(asm):
    """ Generates bytecode for the RC4 cipher (ID 0x10). """
    asm.FUN_START()
    asm.JMP("rc4_body_end")
    asm.label("rc4_cipher_body")
    asm.LD_IX_IMM(KEY_MEM_ADDR); asm.STQ_IX(0)
    asm.LD_IX_IMM(SBOX_MEM_ADDR); asm.MOV_IMM64(2, 0)
    asm.label("ksa_init_loop"); asm.STB_IX_REG(2, 2); asm.INC_REG(2)
    asm.CMP_IMM64(2, 256); asm.JNZ("ksa_init_loop")
    asm.MOV_IMM64(2, 0); asm.MOV_IMM64(3, 0); asm.MOV_IMM64(7, 255)
    asm.label("ksa_scramble_loop")
    asm.LD_IX_IMM(SBOX_MEM_ADDR); asm.LDB_IX_REG(5, 2)
    asm.MOV_REG(4, 2); asm.AND_IMM64(4, 7); asm.LD_IX_IMM(KEY_MEM_ADDR)
    asm.LDB_IX_REG(4, 4); asm.LOGICAL_ADD_REG(3, 5); asm.LOGICAL_ADD_REG(3, 4)
    asm.AND_REG(3, 7); asm.LD_IX_IMM(SBOX_MEM_ADDR); asm.LDB_IX_REG(6, 3)
    asm.STB_IX_REG(6, 2); asm.STB_IX_REG(5, 3); asm.INC_REG(2)
    asm.CMP_IMM64(2, 256); asm.JNZ("ksa_scramble_loop")
    asm.MOV_IMM64(2, 0); asm.MOV_IMM64(3, 0); asm.MOV_IMM64(6, 0)
    asm.label("prga_loop"); asm.CMP_IMM64(1, 0); asm.JZ("prga_loop_end")
    asm.INC_REG(2); asm.AND_REG(2, 7); asm.LD_IX_IMM(SBOX_MEM_ADDR)
    asm.LDB_IX_REG(5, 2); asm.LOGICAL_ADD_REG(3, 5); asm.AND_REG(3, 7)
    asm.LDB_IX_REG(0, 3); asm.STB_IX_REG(0, 2); asm.STB_IX_REG(5, 3)
    asm.LOGICAL_ADD_REG(5, 0); asm.AND_REG(5, 7); asm.LDB_IX_REG(4, 5)
    asm.LDB_IY_REG(5, 6); asm.XOR_REG(5, 4); asm.STB_IY_REG(5, 6)
    asm.INC_REG(6); asm.DEC_REG(1); asm.JMP("prga_loop")
    asm.label("prga_loop_end"); asm.RET()
    asm.label("rc4_body_end"); asm.FUN_END(0x10)

def create_speck64_cipher_func(asm):
    """
    Generates bytecode for Speck-64/128 (ID 0x20) using 32-bit logic.
    R0: 64-bit plaintext (x, y), IX: 128-bit key
    Output: R0 = 64-bit ciphertext
    """
    asm.FUN_START()
    asm.JMP("speck_body_end")
    asm.label("speck_cipher_body")
    
    # Save all registers we might use
    asm.PUSH(0); asm.PUSH(1); asm.PUSH(2); asm.PUSH(3); 
    asm.PUSH(4); asm.PUSH(5); asm.PUSH(6); asm.PUSH(7);
    
    # --- Setup ---
    # R0=x, R1=y (from R0)
    asm.MOV_REG(1, 0); asm.SHR_IMM(1, 32); asm.AND_IMM64(0, MASK_32)
    
    # --- Key Schedule Setup (Unpack 128-bit key from IX) ---
    asm.LDQ_IX(2) # R2 = [k1 | k0]
    asm.PUSH(0); asm.MOV_IMM64(0, 8); asm.ADD_IX_REG(0); asm.POP(0) # IX += 8
    asm.LDQ_IX(3) # R3 = [k3 | k2]
    asm.PUSH(0); asm.MOV_IMM64(0, 8); asm.LOGICAL_SUB_IMM(0, 16); asm.ADD_IX_REG(0); asm.POP(0) # IX -= 8
    
    asm.MOV_REG(4, 2) # R4 = [k1 | k0]
    asm.MOV_REG(5, 3) # R5 = [k3 | k2]

    asm.AND_IMM64(2, MASK_32) # R2 = k0 (k)
    asm.SHR_IMM(4, 32)        # R4 = k1 (l[0])
    
    asm.AND_IMM64(3, MASK_32) # R3 = k2 (l[1])
    asm.SHR_IMM(5, 32)        # R5 = k3 (l[2])
    
    # Swap R3 and R4 to match our desired l = [R3, R4, R5]
    asm.PUSH(7)
    asm.MOV_REG(7, 3) # R7 = k2
    asm.MOV_REG(3, 4) # R3 = k1 (l[0])
    asm.MOV_REG(4, 7) # R4 = k2 (l[1])
    asm.POP(7)
    
    # Final Correct Key State:
    # R2 = k, R3 = l[0], R4 = l[1], R5 = l[2]
    
    asm.MOV_IMM64(6, 0) # R6 = i (round counter)

    asm.label("speck_enc_loop")
    
    # --- 1. Encryption Round: x, y = speck64_encrypt_round(x, y, k) ---
    # R0=x, R1=y, R2=k
    asm.PUSH(7) # Save R7 (scratch)
    
    # x = (ROR32(x, 8) + y) & MASK_32
    asm.MOV_REG(7, 0); asm.ROR32(7, 8) # R7 = ROR32(x, 8)
    asm.MOV_REG(0, 7); asm.LOGICAL_ADD_REG(0, 1); asm.AND_IMM64(0, MASK_32)
    
    # x = (x ^ k) & MASK_32
    asm.XOR_REG(0, 2); asm.AND_IMM64(0, MASK_32)
    
    # y = (ROL32(y, 3) ^ x) & MASK_32
    asm.MOV_REG(7, 1); asm.ROL32(7, 3) # R7 = ROL32(y, 3)
    asm.MOV_REG(1, 7); asm.XOR_REG(1, 0); asm.AND_IMM64(1, MASK_32)

    asm.POP(7) # Restore R7
    
    # --- 2. Check for Last Round ---
    asm.CMP_IMM64(6, 26); asm.JZ("speck_round_end") 
    
    # --- 3. Key Schedule Round: l_val, k = speck64_encrypt_round(l[0], k, i) ---
    # R3=l[0], R2=k, R6=i
    asm.PUSH(0); asm.PUSH(1) # Save plaintext x, y
    
    asm.MOV_REG(0, 3) # x_ks = R3 (l[0])
    asm.MOV_REG(1, 2) # y_ks = R2 (k)
    asm.MOV_REG(2, 6) # k_ks = R6 (i)
    
    # Perform round
    asm.PUSH(7)
    asm.MOV_REG(7, 0); asm.ROR32(7, 8) # R7 = ROR32(x_ks, 8)
    asm.MOV_REG(0, 7); asm.LOGICAL_ADD_REG(0, 1); asm.AND_IMM64(0, MASK_32)
    asm.XOR_REG(0, 2); asm.AND_IMM64(0, MASK_32)
    asm.MOV_REG(7, 1); asm.ROL32(7, 3) # R7 = ROL32(y_ks, 3)
    asm.MOV_REG(1, 7); asm.XOR_REG(1, 0); asm.AND_IMM64(1, MASK_32)
    asm.POP(7)
    
    # R0 holds l_val, R1 holds new k
    
    # --- 4. Update Key State: l = [l[1], l[2], l_val]; k = new_k ---
    asm.MOV_REG(2, 1) # k = new_k
    asm.MOV_REG(3, 4) # l[0] = l[1]
    asm.MOV_REG(4, 5) # l[1] = l[2]
    asm.MOV_REG(5, 0) # l[2] = l_val
    
    asm.POP(1); asm.POP(0) # Restore plaintext x, y
    
    asm.label("speck_round_end")
    asm.INC_REG(6); # i++
    asm.CMP_IMM64(6, 27); asm.JZ("speck_enc_loop_end") 
    
    asm.JMP("speck_enc_loop")
    
    asm.label("speck_enc_loop_end")
    # --- Epilogue ---
    # R0=x, R1=y
    asm.SHL_IMM(1, 32); asm.LOGICAL_ADD_REG(0, 1) # R0 = (y << 32) | x
    
    # Restore registers. Pop R0 into R6 (scratch)
    asm.POP(7); asm.POP(6); asm.POP(5); asm.POP(4);
    asm.POP(3); asm.POP(2); asm.POP(1); asm.POP(6); 
    
    asm.RET()
    asm.label("speck_body_end")
    asm.FUN_END(0x20)

def create_level_check(asm, level_num, check, decrypt_label, decrypt_len):
    """Generates bytecode for a single level check."""
    check_label = f"level_{level_num}_check"
    success_label = f"success_decrypt_{level_num}"
    
    asm.label(check_label)
    asm.LD_IX_IMM(INPUT_BUFFER_START)
    asm.LDQ_IX_OFF(0, check['idx'] * 8) # R0 = input
    asm.MOV_REG(5, 0) # R5 = input
    
    # --- The Check ---
    for val,op in check['ops']:
        if(op=='+'):
            asm.LOGICAL_ADD_IMM(0, val) # Use the new macro
        elif(op=='-'):
            asm.LOGICAL_SUB_IMM(0, val)
        elif(op=='^'):
            asm.XOR_IMM64(0,val)
    
    # --- Speck(res) ---
    asm.LD_IX_IMM(SPECK_KEY_MEM_ADDR)
    asm.MOV_IMM64(1, check['speck_key_lo'])
    asm.STQ_IX(1)
    asm.PUSH(0); asm.MOV_IMM64(0, 8); asm.ADD_IX_REG(0); asm.POP(0)
    asm.MOV_IMM64(1, check['speck_key_hi'])
    asm.STQ_IX(1) 
    
    asm.LD_IX_IMM(SPECK_KEY_MEM_ADDR) # IX = &key[0]
    asm.CALL_ID(0x20) # Call Speck 
    
    asm.CMP_IMM64(0, check['cmp_val'])
    asm.JZ(success_label)

    # Fail Path
    asm.CALL_ID(0x01); asm.HALT()

    # Success Path (SMC)
    asm.label(success_label)
    asm.MOV_REG(0, 5) # Restore original input for key
    asm.emit(0x12); asm.emit_fixup(decrypt_label) # LD_IY_IMM <next>
    asm.MOV_IMM64(1, decrypt_len)
    asm.CALL_ID(0x10); asm.JMP(decrypt_label)


import struct
import random
from asm_helper import *
from enc_helper import *
# --- Constants ---
NUM_INPUTS = 50
NUM_LEVELS = 50

def create_flag_printer(asm):
    asm.label("flag_code")
    asm.emit_string(f"RCTF{{VM_ALU_SMC_RC4_SPECK!_593eb6079d2da6c187ed462b033fee34}}\n")
    asm.HALT()


# --- Main Generator Logic ---
def main():
    print(f"Generating challenge for {NUM_LEVELS} levels...")

    # 1. Generate specs
    LEVELS = []
    correct_keys = []
    random.seed(1337)
    for i in range(NUM_LEVELS):
        correct_input = random.randint(0, MASK_64)
        const_amount=random.randint(3,9)
        ops=[]
        for _ in range(const_amount):
            ops.append((random.randint(0, MASK_64),random.choices(['+','-','^'])[0]))
        # Pre-calculate the result in Python
        res=correct_input
        for val,op in ops:
            if(op=='+'):
                res+=val
            elif(op=='-'):
                res-=val
            elif(op=='^'):
                res^=val
            res&=MASK_64

        speck_key_u128 = random.randint(0, (1 << 128) - 1)
        
        print("before:",hex(res),"key:",hex(speck_key_u128),end='')
        cmp_val = speck64_encrypt(speck_key_u128, res)
        assert speck64_decrypt(speck_key_u128,cmp_val)==res
        print(" result:",hex(cmp_val))
        spec = {
            'idx': i,
            'ops':ops,
            'speck_key_lo': speck_key_u128 & MASK_64,
            'speck_key_hi': (speck_key_u128 >> 64) & MASK_64,
            'cmp_val': cmp_val
        }
        LEVELS.append(spec)
        correct_keys.append((i, spec['idx'], correct_input))

    # --- 2. Pass 1: Layout & Link (All Plaintext) ---
    final_asm = Assembler()

    # --- Registration Phase ---
    final_asm.pad_to(0x0000); final_asm.JMP("reg_phase")
    final_asm.pad_to(0x0003); final_asm.label("main_program")
    final_asm.JMP("level_0_check"); final_asm.pad_to(0x0010); final_asm.HALT()

    final_asm.pad_to(0x0100); final_asm.label("reg_phase")
    create_fail_func(final_asm)
    create_rc4_cipher_func(final_asm) # ID 0x10
    create_speck64_cipher_func(final_asm) # ID 0x20
    final_asm.JMP("main_program")

    # --- Main Challenge Blob (Pass 1: Layout) ---
    final_asm.pad_to(CODE_START_ADDR)
    
    level_addrs = []
    
    for i in range(NUM_LEVELS):
        level_addrs.append(final_asm.get_addr())
        
        if i == NUM_LEVELS - 1:
            next_label = "flag_code"
        else:
            next_label = f"level_{i+1}_check"
            
        create_level_check(final_asm, i, LEVELS[i], next_label, 0) 
    
    level_addrs.append(final_asm.get_addr())
    create_flag_printer(final_asm)
    
    final_asm.link()
    
    # --- Pass 2: Encrypt (In-Place, Backward) ---
    rom = final_asm.bytecode
    
    for i in range(NUM_LEVELS - 1, -1, -1):
        key = correct_keys[i][2] # This is the correct_input
        
        start_addr = level_addrs[i+1]
        end_addr = len(rom)
        decrypt_len = end_addr - start_addr
        
        patch_addr = -1
        check_start = level_addrs[i]
        
        for p in range(check_start, start_addr):
             if (rom[p] == 0x17 and rom[p+1] == 0x00 and rom[p+2] == 0x05 and 
                 rom[p+3] == 0x12 and rom[p+6] == 0x16 and rom[p+7] == 0x01): 
                patch_addr = p + 8
                break
        
        if patch_addr == -1:
            raise ValueError(f"Could not find patch address for level {i}")
            
        rom[patch_addr : patch_addr + 8] = struct.pack('<Q', decrypt_len)
        
        payload_to_encrypt = rom[start_addr : end_addr]
        
        encrypted_payload = rc4_encrypt(key, payload_to_encrypt) 

        rom[start_addr : end_addr] = encrypted_payload

    # --- 3. Write Final File ---
    final_asm.write_to_file("full_vmcode", link_before_write=False)

    # --- 4. Print the solution ---
    print("\n--- Correct Keys ---")
    for i, idx, key in correct_keys:
        print(key)

if __name__ == "__main__":
    main()
from asm_helper import Assembler,INPUT_BUFFER_START,MASK_64
from enc_helper import rc4_encrypt, speck64_decrypt
import re
def replacer(match):
    match_length = len(match.group(0))
    return "f" * match_length
def solve():
    keys=[0 for _ in range(50)]
    asm_add=Assembler()
    asm_add.LOGICAL_ADD_IMM(0,0xAAAAAAAAAAAAAAAA)
    byt = asm_add.bytecode.hex()
    reg_logical_add = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("dead","....")
    # print(reg_logical_add)
    asm_sub=Assembler()
    asm_sub.LOGICAL_SUB_IMM(0,0xAAAAAAAAAAAAAAAA)
    byt = asm_sub.bytecode.hex()
    reg_logical_sub = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("dead","....")
    # print(reg_logical_sub)
    asm_xor=Assembler()
    asm_xor.XOR_IMM64(0,0xAAAAAAAAAAAAAAAA)
    byt = asm_xor.bytecode.hex()
    reg_xor = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("dead","....")

    asm_cmp=Assembler()
    asm_cmp.CMP_IMM64(0,0xAAAAAAAAAAAAAAAA)
    byt = asm_cmp.bytecode.hex()
    reg_cmp = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("dead","....")

    asm_idx=Assembler()
    asm_idx.LD_IX_IMM(INPUT_BUFFER_START)
    asm_idx.LDQ_IX_OFF(0,0xAAAA)
    asm_idx.MOV_REG(5, 0)
    byt = asm_idx.bytecode.hex()
    reg_idx = byt.replace("aaaa","(.{4})").replace("dead","....")
    
    asm_speck=Assembler()
    asm_speck.LD_IX_IMM(0xADDE)
    asm_speck.MOV_IMM64(1, 0xAAAAAAAAAAAAAAAA)
    asm_speck.STQ_IX(1)
    asm_speck.PUSH(0); asm_speck.MOV_IMM64(0, 8); asm_speck.ADD_IX_REG(0); asm_speck.POP(0)
    asm_speck.MOV_IMM64(1, 0xBBBBBBBBBBBBBBBB)
    asm_speck.STQ_IX(1)
    asm_speck.LD_IX_IMM(0xADDE)
    asm_speck.CALL_ID(0x20)
    byt = asm_speck.bytecode.hex()
    reg_speck = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("bbbbbbbbbbbbbbbb","(.{16})").replace("dead","....")

    asm_level_end=Assembler()
    asm_level_end.MOV_IMM64(1, 0xAAAAAAAAAAAAAAAA)
    asm_level_end.CALL_ID(0x10)
    asm_level_end.JMP("w")
    byt = asm_level_end.bytecode.hex()
    reg_end = byt.replace("aaaaaaaaaaaaaaaa","(.{16})").replace("dead","(....)")

    vmcode_ori=bytearray(open('full_vmcode_prod','rb').read())
    vmcode_len=len(vmcode_ori)
    level_start=0x200
    level_end=len(vmcode_ori)
    next_level=0x200
    for _ in range(50):
        add_consts=[]
        sub_consts=[]
        xor_consts=[]
        cmp_consts=[]
        idx_consts=[]
        speck_consts=[]
        start_consts=[]

        vmcode=vmcode_ori[next_level:].hex()

        add_match_iter = re.finditer(reg_logical_add,vmcode,re.S)
        
        for match in add_match_iter:
            add_consts.append(('+',int.from_bytes(bytes.fromhex(match.group(1)),'little'),match.span()))
        vmcode_noadd = re.sub(reg_logical_add,replacer,vmcode,re.S)
        sub_match_iter = re.finditer(reg_logical_sub,vmcode_noadd,re.S)
        
        for match in sub_match_iter:
            sub_consts.append(('-',int.from_bytes(bytes.fromhex(match.group(1)),'little'),match.span()))
        vmcode_noadd_nosub = re.sub(reg_logical_sub,replacer,vmcode_noadd,re.S)
        xor_match_iter = re.finditer(reg_xor,vmcode_noadd_nosub,re.S)
        
        for match in xor_match_iter:
            xor_consts.append(('^',int.from_bytes(bytes.fromhex(match.group(1)),'little'),match.span()))
        cmp_match_iter = re.finditer(reg_cmp,vmcode_noadd_nosub,re.S)
        
        for match in cmp_match_iter:
            cmp_consts.append(('=',int.from_bytes(bytes.fromhex(match.group(1)),'little'),match.span()))
        
        idx_match_iter = re.finditer(reg_idx,vmcode_noadd_nosub,re.S)
        for match in idx_match_iter:
            idx_consts.append(('idx',int.from_bytes(bytes.fromhex(match.group(1)),'little'),match.span()))

        speck_match_iter = re.finditer(reg_speck,vmcode_noadd_nosub,re.S)
        for match in speck_match_iter:
            speck_consts.append(('speck',int.from_bytes(bytes.fromhex(match.group(1)),'little')+(int.from_bytes(bytes.fromhex(match.group(2)),'little')<<64),match.span()))
        end_match_iter = re.finditer(reg_end,vmcode_noadd_nosub,re.S)
        for match in end_match_iter:
            start_consts.append(("start_pc",int.from_bytes(bytes.fromhex(match.group(2)),'little'),match.span()))


        total=add_consts+sub_consts+xor_consts+cmp_consts+idx_consts+speck_consts+start_consts
        order = sorted(total,key=lambda x:x[2][0])
        start = order.index(idx_consts[0])
        end = order.index(start_consts[0])
        enc_cmp_const = order[end-1][1]
        speck_key = order[end-2][1]
        idx = order[start][1]
        cmp_const = speck64_decrypt(speck_key,enc_cmp_const,27)
        order = order[start+1:end-2][::-1]
        for i in order:
            if(i[0]=='+'):
                cmp_const-=i[1]
            elif(i[0]=='-'):
                cmp_const+=i[1]
            elif(i[0]=='^'):
                cmp_const^=i[1]
            cmp_const&=MASK_64

        res=cmp_const
        print(idx//8,"=",res)
        keys[idx//8] = res
        next_level = start_consts[0][1]

        
        vmcode_ori[next_level:]=rc4_encrypt(res,bytearray(vmcode_ori[next_level:]))
    [print(i) for i in keys]

solve()

use std::fs::File;
use std::io::{self, Read, Write, BufRead, BufWriter};
use std::mem;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

// --- VM Constants ---
const MEMORY_SIZE: usize = 65536; // 64KB
const STACK_START: u16 = 0xFFFF;
const INPUT_START: usize = 0xE000;
const NUM_INPUTS: usize = 50;
const INPUT_SIZE_BYTES: usize = 8;

// +++ Debugging +++
const DEBUG: bool = false;

macro_rules! debug_print {
    ($logger:expr, $($arg:tt)*) => {
        if DEBUG {
            if let Some(ref mut log_writer) = $logger {
                write!(log_writer, $($arg)*).unwrap_or_else(|e| {
                    eprintln!("Error writing to log file: {}", e);
                });
            }
        }
    }
}

// --- VM State Structure ---
struct VM {
    memory: Box<[u8; MEMORY_SIZE]>,
    r: [u64; 8],
    pc: u16,
    sp: u16,
    ix: u16,
    iy: u16,
    fpc: u16,
    function_table: [u16; 256],
    zero_flag: bool,
    is_running: bool,
    logger: Option<BufWriter<File>>,
}

impl VM {
    fn new() -> io::Result<Self> {
        let logger = if DEBUG {
            let file = File::create("vm.log")?;
            Some(BufWriter::new(file))
        } else {
            None
        };

        Ok(VM {
            memory: Box::new([0; MEMORY_SIZE]),
            r: [0; 8],
            pc: 0,
            sp: STACK_START,
            ix: 0,
            iy: 0,
            fpc: 0,
            function_table: [0; 256],
            zero_flag: false,
            is_running: false,
            logger, // +++ ADDED
        })
    }
    
    fn flush_log(&mut self) {
        if DEBUG {
            if let Some(ref mut logger) = self.logger {
                logger.flush().unwrap_or_else(|e| {
                    eprintln!("Error flushing log file: {}", e);
                });
            }
        }
    }

    // --- Memory Helper Functions ---
    fn mem_read_u16(&self, addr: u16) -> u16 {
        let mut rdr = &self.memory[addr as usize..];
        rdr.read_u16::<LittleEndian>().unwrap()
    }
    fn mem_read_u64(&self, addr: u16) -> u64 {
        let mut rdr = &self.memory[addr as usize..];
        rdr.read_u64::<LittleEndian>().unwrap()
    }
    fn mem_write_u16(&mut self, addr: u16, val: u16) {
        let mut wtr = &mut self.memory[addr as usize..];
        wtr.write_u16::<LittleEndian>(val).unwrap()
    }
    fn mem_write_u64(&mut self, addr: u16, val: u64) {
        let mut wtr = &mut self.memory[addr as usize..];
        wtr.write_u64::<LittleEndian>(val).unwrap()
    }

    // --- PC-relative fetch functions ---
    fn fetch_u8(&mut self) -> u8 {
        let val = self.memory[self.pc as usize];
        self.pc += 1;
        val
    }
    fn fetch_u16(&mut self) -> u16 {
        let val = self.mem_read_u16(self.pc);
        self.pc += 2;
        val
    }
    fn fetch_u64(&mut self) -> u64 {
        let val = self.mem_read_u64(self.pc);
        self.pc += 8;
        val
    }
    
    // --- Main VM Execution ---
    fn run(&mut self) -> io::Result<()> {
        self.is_running = true;
        
        while self.is_running {
            if self.pc as usize >= MEMORY_SIZE {
                debug_print!(self.logger, "VM Error: PC out of bounds!\n");
                self.is_running = false;
                continue;
            }

            let current_pc = self.pc;
            let opcode = self.fetch_u8();

            debug_print!(self.logger, "[0x{:04X}] ", current_pc);

            match opcode {
                // --- Control Flow ---
                0x01 => { // JMP <addr16>
                    let addr = self.fetch_u16();
                    debug_print!(self.logger, "JMP 0x{:04X}\n", addr);
                    self.pc = addr;
                },
                0x02 => { // JNZ <addr16>
                    let addr = self.fetch_u16();
                    debug_print!(self.logger, "JNZ 0x{:04X} (ZF={})\n", addr, self.zero_flag);
                    if !self.zero_flag { self.pc = addr; }
                },
                0x03 => { // JZ <addr16>
                    let addr = self.fetch_u16();
                    debug_print!(self.logger, "JZ 0x{:04X} (ZF={})\n", addr, self.zero_flag);
                    if self.zero_flag { self.pc = addr; }
                },

                // --- Memory / Register ---
                0x11 => { // LD_IX_IMM <val16>
                    self.ix = self.fetch_u16();
                    debug_print!(self.logger, "LD_IX_IMM 0x{:04X}\n", self.ix);
                },
                0x12 => { // LD_IY_IMM <val16>
                    self.iy = self.fetch_u16();
                    debug_print!(self.logger, "LD_IY_IMM 0x{:04X}\n", self.iy);
                },
                0x15 => { // LDQ_IX <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.r[reg_idx] = self.mem_read_u64(self.ix);
                    debug_print!(self.logger, "LDQ_IX R{} (from 0x{:04X}) -> 0x{:016X}\n", reg_idx, self.ix, self.r[reg_idx]);
                },
                0x16 => { // MOV_IMM64 <reg>, <val64>
                    let reg_idx = self.fetch_u8() as usize;
                    self.r[reg_idx] = self.fetch_u64();
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, "MOV_IMM64 R{}, 0x{:016X}\n", reg_idx, self.r[reg_idx]);
                },
                0x17 => { // MOV_REG <reg_dst>, <reg_src>
                    let reg_dst = self.fetch_u8() as usize;
                    let reg_src = self.fetch_u8() as usize;
                    self.r[reg_dst] = self.r[reg_src];
                    self.zero_flag = self.r[reg_dst] == 0;
                    debug_print!(self.logger, "MOV_REG R{}, R{} -> 0x{:016X}\n", reg_dst, reg_src, self.r[reg_dst]);
                },
                0x18 => { // LDQ_IX_OFF <reg>, <off16>
                    let reg_idx = self.fetch_u8() as usize;
                    let off16 = self.fetch_u16();
                    self.r[reg_idx] = self.mem_read_u64(self.ix.wrapping_add(off16));
                    debug_print!(self.logger, "LDQ_IX_OFF R{} (from 0x{:04X}+{}) -> 0x{:016X}\n", reg_idx, self.ix, off16, self.r[reg_idx]);
                },
                0x19 => { // STQ_IX <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.mem_write_u64(self.ix, self.r[reg_idx]);
                    debug_print!(self.logger, "STQ_IX (to 0x{:04X}) <- R{} (0x{:016X})\n", self.ix, reg_idx, self.r[reg_idx]);
                },
                0x1A => { // LDB_IX_REG <reg_dst>, <reg_offset>
                    let reg_dst = self.fetch_u8() as usize;
                    let reg_off = self.fetch_u8() as usize;
                    let addr_ix = self.ix.wrapping_add(self.r[reg_off] as u16);
                    self.r[reg_dst] = self.memory[addr_ix as usize] as u64;
                    debug_print!(self.logger, "LDB_IX_REG R{}, R{} (from 0x{:04X}) -> 0x{:02X}\n", reg_dst, reg_off, addr_ix, self.r[reg_dst]);
                },
                0x1B => { // STB_IX_REG <reg_src>, <reg_offset>
                    let reg_src = self.fetch_u8() as usize;
                    let reg_off = self.fetch_u8() as usize;
                    let addr_ix = self.ix.wrapping_add(self.r[reg_off] as u16);
                    self.memory[addr_ix as usize] = self.r[reg_src] as u8;
                    debug_print!(self.logger, "STB_IX_REG R{}, R{} (to 0x{:04X}) <- 0x{:02X}\n", reg_src, reg_off, addr_ix, self.r[reg_src]);
                },
                0x1C => { // INC_REG <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.r[reg_idx] = self.r[reg_idx].wrapping_add(1);
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, "INC_REG R{} -> 0x{:016X}\n", reg_idx, self.r[reg_idx]);
                },
                0x1D => { // DEC_REG <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.r[reg_idx] = self.r[reg_idx].wrapping_sub(1);
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, "DEC_REG R{} -> 0x{:016X} (ZF={})\n", reg_idx, self.r[reg_idx], self.zero_flag);
                },
                0x1E => { // SHR_IMM <reg>, <val8>
                    let reg_idx = self.fetch_u8() as usize;
                    let val8 = self.fetch_u8();
                    debug_print!(self.logger, "SHR_IMM R{} (0x{:016X}), {}", reg_idx, self.r[reg_idx], val8);
                    self.r[reg_idx] >>= val8;
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_idx]);
                },
                0x1F => { // ADD_IX_REG <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.ix = self.ix.wrapping_add(self.r[reg_idx] as u16);
                    debug_print!(self.logger, "ADD_IX_REG R{} -> IX=0x{:04X}\n", reg_idx, self.ix);
                },

                // --- Arithmetic / Logic ---
                0x25 => { // AND_REG <reg_dst>, <reg_src>
                    let reg_dst = self.fetch_u8() as usize;
                    let reg_src = self.fetch_u8() as usize;
                    debug_print!(self.logger, "AND_REG R{} (0x{:016X}), R{} (0x{:016X})", reg_dst, self.r[reg_dst], reg_src, self.r[reg_src]);
                    self.r[reg_dst] &= self.r[reg_src];
                    self.zero_flag = self.r[reg_dst] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_dst]);
                },
                0x26 => { // XOR_REG <reg_dst>, <reg_src>
                    let reg_dst = self.fetch_u8() as usize;
                    let reg_src = self.fetch_u8() as usize;
                    debug_print!(self.logger, "XOR_REG R{} (0x{:016X}), R{} (0x{:016X})", reg_dst, self.r[reg_dst], reg_src, self.r[reg_src]);
                    self.r[reg_dst] ^= self.r[reg_src];
                    self.zero_flag = self.r[reg_dst] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_dst]);
                },
                0x27 => { // SHL_IMM <reg>, <val8>
                    let reg_idx = self.fetch_u8() as usize;
                    let val8_shl = self.fetch_u8();
                    debug_print!(self.logger, "SHL_IMM R{} (0x{:016X}), {}", reg_idx, self.r[reg_idx], val8_shl);
                    self.r[reg_idx] <<= val8_shl;
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_idx]);
                },
                0x29 => { // XOR_IMM64 <reg>, <val64>
                    let reg_idx = self.fetch_u8() as usize;
                    let val64 = self.fetch_u64();
                    debug_print!(self.logger, "XOR_IMM64 R{} (0x{:016X}), 0x{:016X}", reg_idx, self.r[reg_idx], val64);
                    self.r[reg_idx] ^= val64;
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_idx]);
                },
                0x2A => { // AND_IMM64 <reg>, <val64>
                    let reg_idx = self.fetch_u8() as usize;
                    let val64 = self.fetch_u64();
                    debug_print!(self.logger, "AND_IMM64 R{} (0x{:016X}), 0x{:016X}", reg_idx, self.r[reg_idx], val64);
                    self.r[reg_idx] &= val64;
                    self.zero_flag = self.r[reg_idx] == 0;
                    debug_print!(self.logger, " -> 0x{:016X}\n", self.r[reg_idx]);
                },
                0x2B => { // LDB_IY_REG <reg_dst>, <reg_offset>
                    let reg_dst = self.fetch_u8() as usize;
                    let reg_off = self.fetch_u8() as usize;
                    let addr_iy = self.iy.wrapping_add(self.r[reg_off] as u16);
                    self.r[reg_dst] = self.memory[addr_iy as usize] as u64;
                    debug_print!(self.logger, "LDB_IY_REG R{}, R{} (from 0x{:04X}) -> 0x{:02X}\n", reg_dst, reg_off, addr_iy, self.r[reg_dst]);
                },
                0x2C => { // STB_IY_REG <reg_src>, <reg_offset>
                    let reg_src = self.fetch_u8() as usize;
                    let reg_off = self.fetch_u8() as usize;
                    let addr_iy = self.iy.wrapping_add(self.r[reg_off] as u16);
                    self.memory[addr_iy as usize] = self.r[reg_src] as u8;
                    debug_print!(self.logger, "STB_IY_REG R{}, R{} (to 0x{:04X}) <- 0x{:02X}\n", reg_src, reg_off, addr_iy, self.r[reg_src]);
                },
                0x32 => { // CMP_IMM64 <reg>, <val64>
                    let reg_idx = self.fetch_u8() as usize;
                    let val64 = self.fetch_u64();
                    self.zero_flag = self.r[reg_idx] == val64;
                    debug_print!(self.logger, "CMP_IMM64 R{} (0x{:016X}), 0x{:016X} (ZF={})\n", reg_idx, self.r[reg_idx], val64, self.zero_flag);
                },

                // --- Function Definition / Calling ---
                0x80 => { // FUN_START
                    self.fpc = self.pc;
                    debug_print!(self.logger, "FUN_START (FPC=0x{:04X})\n", self.fpc);
                },
                0x81 => { // FUN_END <id8>
                    let id = self.fetch_u8() as usize;
                    self.function_table[id] = self.fpc + 3; // +3 to skip JMP
                    debug_print!(self.logger, "FUN_END ID 0x{:02X} -> 0x{:04X}\n", id, self.fpc + 3);
                },
                0x82 => { // CALL_ID <id8>
                    let id = self.fetch_u8() as usize;
                    let addr = self.function_table[id];
                    self.sp = self.sp.wrapping_sub(2); // Push return address
                    self.mem_write_u16(self.sp, self.pc); 
                    debug_print!(self.logger, "CALL_ID 0x{:02X} (-> 0x{:04X}), Pushing 0x{:04X}\n", id, addr, self.pc);
                    self.pc = addr;
                },
                0x83 => { // RET
                    let addr = self.mem_read_u16(self.sp);
                    self.sp = self.sp.wrapping_add(2); // Pop return address
                    debug_print!(self.logger, "RET (-> 0x{:04X})\n", addr);
                    self.pc = addr;
                },
                0x84 => { // PUSH <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.sp = self.sp.wrapping_sub(8);
                    self.mem_write_u64(self.sp, self.r[reg_idx]);
                    debug_print!(self.logger, "PUSH R{} (val=0x{:016X}) -> SP=0x{:04X}\n", reg_idx, self.r[reg_idx], self.sp);
                },
                0x85 => { // POP <reg>
                    let reg_idx = self.fetch_u8() as usize;
                    self.r[reg_idx] = self.mem_read_u64(self.sp);
                    self.sp = self.sp.wrapping_add(8);
                    debug_print!(self.logger, "POP R{} (val=0x{:016X}) <- SP=0x{:04X}\n", reg_idx, self.r[reg_idx], self.sp.wrapping_sub(8));
                },

                // --- I/O ---
                0x90 => { // OUT_IMM <char8>
                    let c = self.fetch_u8();
                    debug_print!(self.logger, "OUT_IMM '{}'\n", c as char);
                    io::stdout().write_all(&[c])?;
                    io::stdout().flush()?;
                },
                0xFF => { // HALT
                    debug_print!(self.logger, "HALT\n");
                    self.is_running = false;
                    self.flush_log(); 
                },
                
                0x00 => { // NOP (padding)
                    debug_print!(self.logger, "NOP\n");
                },

                _ => {
                    debug_print!(self.logger, "VM Error: Unknown opcode 0x{:02X} at 0x{:04X}\n", opcode, current_pc);
                    self.is_running = false;
                    self.flush_log(); 
                }
            }
        }
        
        self.flush_log();
        Ok(())
    }
}


fn main() -> io::Result<()> {
    let mut vm = VM::new()?; 

    println!("Enter {} 64-bit keys:", NUM_INPUTS);
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    for i in 0..NUM_INPUTS {
        let mut line = String::new();
        if handle.read_line(&mut line)? == 0 {
            eprintln!("Error: End of input reached unexpectedly.");
            return Ok(()); 
        }
        
        let input_val: u64 = match line.trim().parse() {
            Ok(num) => num,
            Err(e) => {
                eprintln!("Error reading input: {}. Please enter a valid number.", e);
                return Ok(()); 
            }
        };
        
        let addr = INPUT_START + (i * INPUT_SIZE_BYTES);
        vm.mem_write_u64(addr as u16, input_val);
    }

    let mut file = File::open("full_vmcode")?;
    let bytes_read = file.read(&mut vm.memory[..INPUT_START])?;
    println!("Loaded {} bytes of VM code.", bytes_read);

    println!("Starting VM...\n---");
    if let Err(e) = vm.run() {
        eprintln!("VM runtime error: {}", e);
    }
    println!("\n---\nVM Halted.");
    
    vm.flush_log();
    
    Ok(())
}

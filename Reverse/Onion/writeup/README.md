# Onion

**Category:** Reverse Engineering / Virtual Machine  

## 1. Challenge Overview

This is a classic Virtual Machine (VM) reverse engineering challenge. We are provided with a bytecode file, `full_vmcode`, and a Rust-based VM launcher.

The objective is to pass **50 levels**. Each level requires a correct 64-bit integer input. If the input is correct, the VM decrypts the next level and continues. If incorrect, the VM executes a `FAIL` function and halts.

## 2. Initial Analysis

The VM initializes by registering three critical system functions at the beginning of execution:
1.  **FAIL (ID 0x01):** Prints "Fail" and halts execution.
2.  **RC4 (ID 0x10):** A stream cipher used for **Self-Modifying Code (SMC)**. It decrypts the next level's bytecode using the user's input as the key.
3.  **SPECK (ID 0x20):** The **SPECK-64/128** block cipher, used as the last step before comparing to a hardcoded value.

## 3. Level Logic & Obfuscation

Every level follows an identical logic flow, though the constants change.

### Arithmetic Macro
The VM lacks native 64-bit `ADD` and `SUB` instructions. To perform arithmetic, the bytecode implemented "Emulated Arithmetic" using sequences of bitwise operations.

* **Addition:** Implemented using `XOR`, `AND`, and `SHIFT` loops (Carry-Lookahead logic).
* **Subtraction:** Implemented using Two's Complement logic (Bitwise NOT + 1).
* **Rotation:** Implemented using `SHL`, `SHR`, and `OR`.


### The Check Formula
For any given Level $N$, the logic simplifies to:

1.  **Input:** Load I index of 50 inputs 
    $$K_{i} = Keys[i]$$
2.  **Arithmetic:** Apply a sequence of operations; example:
    $$Val = ((K_{i} + C_1) - C_3) \oplus C_2$$
3.  **Encryption:** Encrypt the result using Speck-64/128 with a level-specific key:
    $$Enc = \text{Speck64\_Encrypt}(Val, K_{speck})$$
4.  **Validation:** Compare the result against a hardcoded target:
    $$Enc == Target$$
5.  **Progression:** If the check passes, use $K_{i}$ as the RC4 key to decrypt Level $N+1$ and jump to it.

## 4. Solution Strategy

Since the check relies on a cryptographic hash (Speck) of the input, we cannot use symbolic execution easily. However, because the binary contains the *comparison target* and the *encryption key*, we can solve this in reverse.

**The Strategy:**
1.  **Parse the Bytecode:** Instead of running the VM, we write a script to parse the `full_vmcode` file.
2.  **Extract Constants:** For each level, regex or pattern-match to find:
    * The arithmetic constants, operations and order (ex: $C_1(+), C_3(-), C_2(\oplus),...$).
    * The Speck Key ($K_{speck}$).
    * The Comparison Target ($Target$).
    * The input index ($i$)
3.  **Reverse the Math:**
    * First, decrypt the target: 
        $$Val = \text{Speck64\_Decrypt}(Target, K_{speck})$$
    * Second, invert the arithmetic; example:
        $$K_{i} = ((Val \oplus C_2) + C_3) - C_1$$
1.  **Extract the flag:**
    * Sending the list of correct keys will print the flag

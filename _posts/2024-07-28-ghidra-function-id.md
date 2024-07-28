---
layout: "post"
title:  "Computing Ghidra Function ID Hashes"
date:   "2024-07-28"
author: "Joren Vrancken"
lang: "en-US"
---

During reverse engineering, an analyst is trying to answer specific questions about the binary they are analyzing. For example, "how does this malware sample encrypt files?" or "what is the root cause of the authentication bug in this router firmware?". Often only a small subset of the functions in the binary are relevant to answer these questions and finding the relevant functions is a big part of the reverse engineering process. Many functions in a binary are uninteresting to analyzing the functionality of the binary itself, because their functionality is already well-understood (e.g. library code) or because they implement boilerplate functionality (e.g. `mainCRTStartup` in Windows executables). An analyst would like to know which function in a Windows executable is `mainCRTStartup`, but does not want to spend time on actually analyzing `mainCRTStartup`.

However, identifying which functions in a binary are _interesting_ and which are _uninteresting_ library code is hard. To combat this problem, reverse engineering suites (i.e. [IDA Pro](https://hex-rays.com/ida-pro/), [Ghidra](https://ghidra-sre.org/) and [Binary Ninja](https://binary.ninja/)) try to automate detection and classification of uninteresting functions. Although they all employ a different solution, the fundamental idea behind their solutions is the same: compute a list of signatures for known functions (i.e. with symbols) to match against unknown functions (i.e. without symbols).

I was curious how these function identification systems worked under the hood. The system that IDA Pro uses, F.L.I.R.T. signatures, is [relatively well documented](https://hex-rays.com/products/ida/tech/flirt/in_depth/). However, I couldn't find any technical details on how the function identification feature of Ghidra, Function ID, works. Specically, how Ghidra generates signatures from functions. In this blog I would like to explore how Function ID actually works and generates signatures.

### Function ID
Ghidra comes with a lot of documentation, including [documentation on Function ID](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/doc/fid.xml). This documentation mostly contains information on how users can use Function ID (e.g. which settings are available) and how functions are matched against a database of signatures (_libraries_).

However, the documentation does say:
> For each function, the analyzer computes a hash of its body and uses this as a key to look up matching functions in an indexed database of known software.

When Ghidra analyzes a binary, it computes two hash values for each function: the _full hash_ and the _specific hash_. The full hash is based on specific properties of each of its Assembly instructions: the instruction bytes with any operand bytes masked out and register operands. The specific hash is based on more properties: the instruction bytes (with any operand bytes masked out), the register operands, the immediate value operands and the address operands.

The documentation does not tell us how these hashes are actually computed. Luckily, Ghidra is [open source](https://github.com/NationalSecurityAgency/ghidra) and as such the source of [the Function ID hashing is also open source](https://github.com/NationalSecurityAgency/ghidra/blob/2517a3234822de74e05e642a55f79d8f3b4c5198/Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/hash/MessageDigestFidHasher.java).

### The Algorithm

By reading the code, we can deduce the Function ID hashing algorithm:
```python
01 full_hash = fnv1a64_hash
02 specific_hash = fnv1a64_hash
03
04 for each instruction:
05
06    for each operand in the instruction:
07
08        operand_value_full = (instruction index + 1) * 7777
09        operand_value_specific = (instruction index + 1) * 7777
10
11        for each op_object in the operand:
12
13            if the op_object is a register:
14                operand_value_full += (op_object offset in register space + 7654321) * 98777
15                operand_value_specific += (op_object offset in register space + 7654321) * 98777
16
17            if the op_object is an address:
18                operand_value_full += 0xFEEDDEAD
19                operand_value_specific += (0xFEEDDEAD + 1234567) * 67999
20
21            if the op_object is a constant value:
22                operand_value_full += 0xFEEDDEAD
23                operand_value_specific += (op_object + 1234567) * 67999
24
25        full_hash.update(operand_value_full)
26        specific_hash.update(operand_value_specific)
27
28    full_hash.update(masked instruction bytes)
29    specific_hash.update(masked instruction bytes)
```
_We simplified and left out some edge cases._

The input for this algorithm is a single disassembled function.
Although this is simplified pseudocode, there is still a lot going on. Let's go over each part in detail.

#### Lines 1-2: Initializing the Hashes
We initialize the full hash and the specific hash.

Function ID hashes are actually [Fowler–Noll–Vo](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function) (FNV) hashes, specifically they are 64-bit FNV-1a hashes[^1]. The FNV hashing scheme is primarily meant to be fast (as opposed to secure), making it suitable for checksums.

The FNV-1a algorithm is straightforward and can be implemented in a few lines of Python:
```Python
FNV1A_OFFSET_BASIS = 0xcbf29ce484222325
FNV1A_PRIME = 0x100000001b3

def fnv1a64(data: bytes) -> int:
    result = FNV1A_OFFSET_BASIS
    for b in data:
        result ^= b
        result = (result * FNV1A_PRIME) % 2**64
    return result
```

#### Lines 4-6: Looping over each Operand in each Instruction
Both hashes are updated with a value for each _operand_ in each _instruction_ in the function.
For example, take the following to instructions:
```
xor rdi, rax
mov rbx, 1
```

We would compute 8 operand values: an update value for `rdi`, `rax`, `rbx` and `1` for both the full hash and the specific hash.

#### Lines 8-9: The Operand-specific Intermediate Value
Each operand value is initialized as `(operand index + 1) * 7777`.

#### Lines 11: Looping over each Object in the Operand
Each operand is split into _objects_, where an object is either a constant (i.e. immediate or relative address) or a register.

For example, take the following instruction:
```
mov edx, dword ptr [rbp + 0x10]
```

This is one instruction (`mov`), with two operands. The first operand (`edx`) has one object: `edx`. The second operand (`dword ptr [rbp + 0x10]`) has two objects: `rbp` and `0x10`.

#### Lines 13-15: If the Object is a Register
If the object is a register, the operand value is updated with: `(op_object offset in register space + 7654321) * 98777`.

`op_object offset in register space` requires some additional explanation.
Ghidra's disassembler is based on [SLEIGH](https://fossies.org/linux/ghidra/GhidraDocs/languages/html/sleigh.html), an instruction set specification language. SLEIGH is a powerful tool that lets you define a new instruction set that immediately plugs into all the features of Ghidra. For example, Ghidra would be able to decompile the new instruction set, just based on its SLEIGH specification.

Registers are implemented as a pseudo-memory space, called register space, in which each register has an address. For example, the ([x86 SLEIGH spec](https://github.com/NationalSecurityAgency/ghidra/blob/2517a3234822de74e05e642a55f79d8f3b4c5198/Ghidra/Processors/x86/data/languages/ia.sinc)) defines the following register space for the 64 bit registers:
```
define register offset=0 size=8 [ RAX RCX RDX RBX RSP RBP RSI RDI ];
```

This should be read as:
* Address of RAX: 0x0
* Address of RCX: 0x8
* Address of RDX: 0x10
* Address of RDX: 0x18
<ol>
...
</ol>
* Address of RDI: 0x38

#### Lines 17-19: If the Object is an Address
If the object is an address, `0xFEEDDEAD` is added to the operand value of the full hash and `(0xFEEDDEAD + 1234567) * 67999` is added to the operand value of the specific hash.

Whether a value is an address or a constant value is instruction-specific and requires understanding the context of the instruction.

For example:
```
mov eax, 0x14000155d
jmp 0x14000155d
```
In the first instruction `0x14000155d` is a constant value that is moved into the `eax` register. But in the second value `0x14000155d` is an address that the instruction will jump to.
As a jump instruction will always require an address, we can infer that `0x14000155d` is actually an address and not a constant value.

#### Lines 17-19: If the Object is a Constant Value
If the object is a constant value, `0xFEEDDEAD` is added to the operand value of the full hash and `(value + 1234567) * 67999` is added to the operand value of the specific hash.

#### Lines 25-26: Updating the Hashes with the Intermediate Value
After we have looked at each object in an operand, we should have two updated values: the operand value of the full hash and the operand value of the specific hash.
Their respective hashes are updated with these values.

#### Lines 28-29: Updating the Hashes with the Masked Instruction Bytes
Finally, after having looked at a full instruction, we add the masked instruction bytes themselves to the hash.

The masked instruction bytes are the bytes of the instructions with all variable bits zeroed out. For example, the bytes `89 4d 10` disassemble to `mov dword ptr [rbp + 0x10], ecx`, but the bytes `89 46 25` disassemble to `mov dword ptr [rsi + 0x25], eax`. Both are `mov` instructions but their operands (i.e. the variable bits) are different. When Ghidra masks them, they are both reduced to their base: `89 40 00`.

As the [x86 instruction set is complex](http://ref.x86asm.net/coder64.html) it is not always clear (i.e. subjective) which bits in an instruction should be considered variable. For example, one could argue that `89 4d 10` should not be masked to `89 40 00`, but to `89 00 00`. Ghidra defines which bits should variable in the SLEIGH specifications of each instruction set.

#### End Result
At the end we have two hashes: the full hash and the specific hash. These two hashes represent the Function ID hashes for this function.

### Computing an Example by Hand

Now we know how to compute the Function ID hashes for a function, let's try to compute a hash by hand.

#### The Example Program
We will use the following dummy C function:
```c
int custom_sum(int a, int b){

    if (a == 1){
      return a + b + 10;
    }
    return a + b;
}
```

Ghidra disassembles this function as follows:
```
                             **************************************************************
                             * custom_sum(int, int)                                       *
                             **************************************************************
                             int __fastcall custom_sum(int param_1, int param_2)
             int               EAX:4          <RETURN>
             int               ECX:4          param_1
             int               EDX:4          param_2
             undefined4        Stack[0x10]:4  local_res10                             XREF[3]:     140001547(W),
                                                                                                   140001553(R),
                                                                                                   140001560(R)
             undefined4        Stack[0x8]:4   local_res8                              XREF[4]:     140001544(W),
                                                                                                   14000154a(R),
                                                                                                   140001550(R),
                                                                                                   14000155d(R)
                             .text                                           XREF[2]:     main:14000158a(c), 1400cd084(*)
                             _Z10custom_sumii
                             custom_sum
       140001540 55              PUSH       RBP
       140001541 48 89 e5        MOV        RBP,RSP
       140001544 89 4d 10        MOV        dword ptr [RBP + local_res8],param_1
       140001547 89 55 18        MOV        dword ptr [RBP + local_res10],param_2
       14000154a 83 7d 10 01     CMP        dword ptr [RBP + local_res8],0x1
       14000154e 75 0d           JNZ        LAB_14000155d
       140001550 8b 55 10        MOV        param_2,dword ptr [RBP + local_res8]
       140001553 8b 45 18        MOV        EAX,dword ptr [RBP + local_res10]
       140001556 01 d0           ADD        EAX,param_2
       140001558 83 c0 0a        ADD        EAX,0xa
       14000155b eb 08           JMP        LAB_140001565
                             LAB_14000155d                                   XREF[1]:     14000154e(j)
       14000155d 8b 55 10        MOV        param_2,dword ptr [RBP + local_res8]
       140001560 8b 45 18        MOV        EAX,dword ptr [RBP + local_res10]
       140001563 01 d0           ADD        EAX,param_2
                             LAB_140001565                                   XREF[1]:     14000155b(j)
       140001565 5d              POP        RBP
       140001566 c3              RET
```

### Initializing the Hashes
We initialize the full and the specific hash with the 64-bit FNV-1a hashes initialization values:
```
full_hash = 0xCBF29CE484222325
specific_hash = 0xCBF29CE484222325
```

#### Instruction 0: push rbp
The first instruction only has one operand with one object: `rbp`.
In the Ghidra register space, `rbp` has address 0x28.
```
# Operand: rbp
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

full_hash.update(operand_value_full % 2**32) = 0xf50056b7de4a5db6
specific_hash.update(operand_value_specific % 2**32) = 0xf50056b7de4a5db6
```

The instruction bytes (`55`) are masked as `50`:
```
full_data.update(50) = 0x99f1406eb85d8dd2
specific_hash.update(50) = 0x99f1406eb85d8dd2
```

#### Instruction 1: mov rbp, rsp
```
# Operand: rbp
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

full_hash.update(operand_value_full % 2**32) = 0x2741dfbde8e7699
specific_hash.update(operand_value_specific % 2**32) = 0x2741dfbde8e7699

# Operand: rsp
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: rsp
operand_value_full += (0x20 + 7654321) * 98777 = 0xb0098651eb
operand_value_specific += (0x20 + 7654321) * 98777 = 0xb0098651eb

full_hash.update(operand_value_full % 2**32) = 0x3f0a57ea427ab9c6
specific_hash.update(operand_value_specific % 2**32) = 0x3f0a57ea427ab9c6
```

The instruction bytes (`48 89 E5`) are masked as `48 89 C0`:
```
full_data.update(48 89 C0) = 0x440fbf13d494a0fb
specific_hash.update(48 89 C0) = 0x440fbf13d494a0fb
```

#### Instruction 2: mov dword ptr [rbp + 0x10], ecx
```
# Operand: dword ptr [rbp + 0x10]
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

# Operand object: 0x10
operand_value_full += 0xFEEDDEAD = 0xb1088020ff
operand_value_specific += (16 + 1234567) * 67999 = 0xc39567d91b

full_hash.update(operand_value_full % 2**32) = 0x9baee3c50e55144a
specific_hash.update(operand_value_specific % 2**32) = 0xad13e870efab6763

# Operand: ecx
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: ecx
operand_value_full += (0x8 + 7654321) * 98777 = 0xb009622593
operand_value_specific += (0x8 + 7654321) * 98777 = 0xb009622593

full_hash.update(operand_value_full % 2**32) = 0xf73f06a6ba26de4d
specific_hash.update(operand_value_specific % 2**32) = 0x5efe038571c4ced0
```

The instruction bytes (`89 4D 10`) are masked as `89 40 00`:
```
full_data.update(89 40 00) = 0x28531e9efc920f2c
specific_hash.update(89 40 00) = 0x4f1abfd3da39edb3
```

#### Instruction 3: mov dword ptr [rbp + 0x18], edx
```
# Operand: mov dword ptr [rbp + 0x18]
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

# Operand object: 0x18
operand_value_full += 0xFEEDDEAD = 0xb1088020ff
operand_value_specific += (24 + 1234567) * 67999 = 0xc395702613

full_hash.update(operand_value_full % 2**32) = 0x226284fe00a74d49
specific_hash.update(operand_value_specific % 2**32) = 0xf8c1af1b8aa00269

# Operand: edx
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: edx
operand_value_full += (0x10 + 7654321) * 98777 = 0xb0096e345b
operand_value_specific += (0x10 + 7654321) * 98777 = 0xb0096e345b

full_hash.update(operand_value_full % 2**32) = 0xb1d3d5ef614a9c13
specific_hash.update(operand_value_specific % 2**32) = 0xfb0ee854a6852833
```

The instruction bytes (`89 55 18`) are masked as `89 40 00`:
```
full_data.update(89 40 00) = 0xcb0adc33bbe6311e
specific_hash.update(89 40 00) = 0x22aa628e01e98a7e
```

#### Instruction 4: cmp dword ptr [rbp + 0x10], 1
```
# Operand: dword ptr [rbp + 0x10]
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

# Operand object: 0x10
operand_value_full += 0xFEEDDEAD = 0xb1088020ff
operand_value_specific += (16 + 1234567) * 67999 = 0xc39567d91b

full_hash.update(operand_value_full % 2**32) = 0x69845e227b577137
specific_hash.update(operand_value_specific % 2**32) = 0x89f5c732c59961ce

# Operand: 0x1
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: 0x1
operand_value_full += 0xFEEDDEAD = 0xfeee1b6f
operand_value_specific += (1 + 1234567) * 67999 = 0x138bc6433a

full_hash.update(operand_value_full % 2**32) = 0x52a1fab76df60679
specific_hash.update(operand_value_specific % 2**32) = 0x4cddc87871d73476
```

The instruction bytes (`83 7D 10 01`) are masked as `83 78 00 00`:
```
full_data.update(83 78 00 00) = 0x4b68c8bced7bab92
specific_hash.update(83 78 00 00) = 0x98b198d254c20abd
```

#### Instruction 5: jne 0x14000155d
```
# Operand: 0x14000155d
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: 0x14000155d
operand_value_full += 0xFEEDDEAD = 0xfeedfd0e
operand_value_specific += (0xFEEDDEAD + 1234567) * 67999 = 0x108961d037dad

full_hash.update(operand_value_full % 2**32) = 0xc5dd45f9964fc504
specific_hash.update(operand_value_specific % 2**32) = 0x146cfe1e83ae4093
```

The instruction bytes (`75 0D`) are masked as `75 00`:
```
full_data.update(75 00) = 0x8a6db7e159bbd219
specific_hash.update(75 00) = 0x17946d031c4056d6
```

#### Instruction 6: mov edx, dword ptr [rbp + 0x10]
```
# Operand: edx
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: edx
operand_value_full += (0x10 + 7654321) * 98777 = 0xb0096e15fa
operand_value_specific += (0x10 + 7654321) * 98777 = 0xb0096e15fa

full_hash.update(operand_value_full % 2**32) = 0x61eba37e808638c5
specific_hash.update(operand_value_specific % 2**32) = 0xd50f26f91e31abfa

# Operand: dword ptr [rbp + 0x10]
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb0099260b3
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb0099260b3

# Operand object: 0x10
operand_value_full += 0xFEEDDEAD = 0xb108803f60
operand_value_specific += (16 + 1234567) * 67999 = 0xc39567f77c

full_hash.update(operand_value_full % 2**32) = 0x2d78f452726a531a
specific_hash.update(operand_value_specific % 2**32) = 0x5fa501a0229b92c5
```

The instruction bytes (`8B 55 10`) are masked as `8B 40 00`:
```
full_data.update(8B 40 00) = 0xea6a12d7970de59b
specific_hash.update(8B 40 00) = 0x58819af7b62ee85a
```

#### Instruction 7: mov eax, dword ptr [rbp + 0x18]
```
# Operand: eax
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: eax
operand_value_full += (0x0 + 7654321) * 98777 = 0xb00955f86a
operand_value_specific += (0x0 + 7654321) * 98777 = 0xb00955f86a

full_hash.update(operand_value_full % 2**32) = 0x6fe6e99b31656b9b
specific_hash.update(operand_value_specific % 2**32) = 0xf6e0b7436930d2a

# Operand: dword ptr [rbp + 0x18]
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb0099260b3
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb0099260b3

# Operand object: 0x18
operand_value_full += 0xFEEDDEAD = 0xb108803f60
operand_value_specific += (24 + 1234567) * 67999 = 0xc395704474

full_hash.update(operand_value_full % 2**32) = 0x2adf6be5a957b7f4
specific_hash.update(operand_value_specific % 2**32) = 0x4fbb95f10ea86997
```

The instruction bytes (`8B 45 18`) are masked as `8B 40 00`:
```
full_data.update(8B 40 00) = 0x8253a271b487c995
specific_hash.update(8B 40 00) = 0xa0a7242b2bc4c7f4
```

#### Instruction 8: add eax, edx
```
# Operand: eax
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: eax
operand_value_full += (0x0 + 7654321) * 98777 = 0xb00955f86a
operand_value_specific += (0x0 + 7654321) * 98777 = 0xb00955f86a

full_hash.update(operand_value_full % 2**32) = 0x3d01f6b2fb5118a1
specific_hash.update(operand_value_specific % 2**32) = 0xf4b0866baef15d60

# Operand: edx
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: edx
operand_value_full += (0x10 + 7654321) * 98777 = 0xb0096e345b
operand_value_specific += (0x10 + 7654321) * 98777 = 0xb0096e345b

full_hash.update(operand_value_full % 2**32) = 0xa4e3904090e0c79b
specific_hash.update(operand_value_specific % 2**32) = 0xd962fb16ff05ef5e
```

The instruction bytes (`01 D0`) are masked as `01 C0`:
```
full_data.update(01 C0) = 0x38319890143118ea
specific_hash.update(01 C0) = 0xb72ab2dcf9f2fff7
```

#### Instruction 9: add eax, 0xa
```
# Operand: eax
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: eax
operand_value_full += (0x0 + 7654321) * 98777 = 0xb00955f86a
operand_value_specific += (0x0 + 7654321) * 98777 = 0xb00955f86a

full_hash.update(operand_value_full % 2**32) = 0xe2bbab0ee418dfba
specific_hash.update(operand_value_specific % 2**32) = 0xfb625cf75ce4ea6f

# Operand: 0xa
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: 0xa
operand_value_full += 0xFEEDDEAD = 0xfeee1b6f
operand_value_specific += (10 + 1234567) * 67999 = 0x138bcf99d1

full_hash.update(operand_value_full % 2**32) = 0x5850ee37b952d178
specific_hash.update(operand_value_specific % 2**32) = 0x856a41c1ff7bd183
```

The instruction bytes (`83 C0 0A`) are masked as `83 C0 00`:
```
full_data.update(83 C0 00) = 0x5e55071c5b6d8269
specific_hash.update(83 C0 00) = 0x623b60101a3cf9c0
```

#### Instruction 10: jmp 0x140001565

This instruction has one operand, with one object: 0x140001565. Although this operand looks like a constant value, the context of the program (i.e. the jump instruction) tells us that this is actually an address. As such, it is treated as an address value and not a constant value for the Function ID hashes.
```
# Operand: 0x140001565
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: 0x140001565
operand_value_full += 0xFEEDDEAD = 0xfeedfd0e
operand_value_specific += (0xFEEDDEAD + 1234567) * 67999 = 0x108961d037dad

full_hash.update(operand_value_full % 2**32) = 0xa0970b766787af93
specific_hash.update(operand_value_specific % 2**32) = 0x7e95e9db8dc4036a
```

The instruction bytes (`EB 08`) are masked as `EB 00`:
```
full_data.update(EB 00) = 0xdc9972d344428238
specific_hash.update(EB 00) = 0x2bffa4668a81f2a9
```

#### Instruction 11: mov edx, dword ptr [rbp + 0x10]
```
# Operand: edx
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: edx
operand_value_full += (0x10 + 7654321) * 98777 = 0xb0096e15fa
operand_value_specific += (0x10 + 7654321) * 98777 = 0xb0096e15fa

full_hash.update(operand_value_full % 2**32) = 0x777acd37f4023b4
specific_hash.update(operand_value_specific % 2**32) = 0x519af7334ad54395

# Operand: dword ptr [rbp + 0x10]
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb0099260b3
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb0099260b3

# Operand object: 0x10
operand_value_full += 0xFEEDDEAD = 0xb108803f60
operand_value_specific += (16 + 1234567) * 67999 = 0xc39567f77c

full_hash.update(operand_value_full % 2**32) = 0x2ad71692f9135fb
specific_hash.update(operand_value_specific % 2**32) = 0xfc15e8acdb02d8be
```

The instruction bytes (`8B 55 10`) are masked as `8B 40 00`:
```
full_data.update(8B 40 00) = 0x65cc9f51d05b0790
specific_hash.update(8B 40 00) = 0x889b8eb509f6cba7
```

#### Instruction 12: mov eax, dword ptr [rbp + 0x18]
```
# Operand: eax
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: eax
operand_value_full += (0x0 + 7654321) * 98777 = 0xb00955f86a
operand_value_specific += (0x0 + 7654321) * 98777 = 0xb00955f86a

full_hash.update(operand_value_full % 2**32) = 0xe80ce9865b0acdf4
specific_hash.update(operand_value_specific % 2**32) = 0xf5dfa2d223978f1f

# Operand: dword ptr [rbp + 0x18]
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb0099260b3
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb0099260b3

# Operand object: 0x18
operand_value_full += 0xFEEDDEAD = 0xb108803f60
operand_value_specific += (24 + 1234567) * 67999 = 0xc395704474

full_hash.update(operand_value_full % 2**32) = 0x81de944741a37dbb
specific_hash.update(operand_value_specific % 2**32) = 0xd5b3441063a6e85a
```

The instruction bytes (`8B 45 18`) are masked as `8B 40 00`:
```
full_data.update(8B 40 00) = 0x32ce1733c5730950
specific_hash.update(8B 40 00) = 0xb54e2c1184ccabdb
```

#### Instruction 13: add eax, edx
```
# Operand: eax
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: eax
operand_value_full += (0x0 + 7654321) * 98777 = 0xb00955f86a
operand_value_specific += (0x0 + 7654321) * 98777 = 0xb00955f86a

full_hash.update(operand_value_full % 2**32) = 0xe6819d111e3b6634
specific_hash.update(operand_value_specific % 2**32) = 0x2f1a3f190cbc1b5b

# Operand: edx
operand_value_full = (1 + 1) * 7777 = 0x3cc2
operand_value_specific = (1 + 1) * 7777 = 0x3cc2

# Operand object: edx
operand_value_full += (0x10 + 7654321) * 98777 = 0xb0096e345b
operand_value_specific += (0x10 + 7654321) * 98777 = 0xb0096e345b

full_hash.update(operand_value_full % 2**32) = 0xbfc744730ec127a2
specific_hash.update(operand_value_specific % 2**32) = 0xcef5f238fb4397bd
```

The instruction bytes (`01 D0`) are masked as `01 C0`:
```
full_data.update(01 C0) = 0x5e354c04f2599bdb
specific_hash.update(01 C0) = 0xd54770745cd76ddc
```

#### Instruction 14: pop rbp
```
# Operand: rbp
operand_value_full = (0 + 1) * 7777 = 0x1e61
operand_value_specific = (0 + 1) * 7777 = 0x1e61

# Operand object: rbp
operand_value_full += (0x28 + 7654321) * 98777 = 0xb009924252
operand_value_specific += (0x28 + 7654321) * 98777 = 0xb009924252

full_hash.update(operand_value_full % 2**32) = 0x573e623a16195188
specific_hash.update(operand_value_specific % 2**32) = 0xf882e43be5b81d97
```

The instruction bytes (`5D`) are masked as `58`:
```
full_data.update(58) = 0x5852b8b38d060470
specific_hash.update(58) = 0xfe87a0c757daa6bd
```

#### Instruction 15: ret
The `ret` instruction does not have any operands.

The instruction bytes (`C3`) are masked as `C3`:
```
full_data.update(C3) = 0x1a948c18a139fc29
specific_hash.update(C3) = 0x5b1cb0ba4888e81a
```

#### Final result
After a lot of calculations, we end up with the following hashes:
```
Full hash: 0x1a948c18a139fc29
Specific hash: 0x5b1cb0ba4888e81a
```

#### Validating our Work
But do the hashes we computed actually match the hashes Ghidra generates for this function?

Ghidra has a [Function ID plugin](https://fossies.org/linux/ghidra/Ghidra/Features/FunctionID/src/main/help/help/topics/FunctionID/FunctionIDPlugin.html) that allows users to create (exportable) Function ID databases and debug Function ID.

This plugin has a search feature, that allows us to search for our function:
![Ghidra Function ID Plugin Search Screenshot](/assets/function-id-by-hand/ghidra-screenshot.png)

As we can see, the values we computed match those Ghidra computed!

### Discussion
In this post, we discussed Ghidra Function ID, specially its hashes. We learned how to compute these hashes by hand.

The original goal of this project was to create a Python script to generate Function ID hashes without any dependencies on Ghidra. However, we saw that the computation of the hashes rely on Ghidra-specific data: the address of registers in register-space and the masking of instruction bytes. Because of these dependencies it does not seem possible to create a program that generates Function ID hashes without relying on Ghidra. It also means that the Function ID hashes might change if Ghidra (specifically the SLEIGH specification) changes.

[Appendix A](#appendix-a) contains the source code I used to compute the hashes, based on [capstone](https://www.capstone-engine.org/). This code is proof-of-concept and cuts some corners to deal with the register-space and instruction masking.

### Appendix A

```python
import capstone

FNV1A64_INITIAL_STATE = 0xCBF29CE484222325
FNV1A64_PRIME = 0x100000001B3

CUSTOM_SUM_ADDR = 0x140001540
CUSTOM_SUM_BYTES = (
    b"\x55"
    b"\x48\x89\xe5"
    b"\x89\x4d\x10"
    b"\x89\x55\x18"
    b"\x83\x7d\x10\x01"
    b"\x75\x0d"
    b"\x8b\x55\x10"
    b"\x8b\x45\x18"
    b"\x01\xd0"
    b"\x83\xc0\x0a"
    b"\xeb\x08"
    b"\x8b\x55\x10"
    b"\x8b\x45\x18"
    b"\x01\xd0"
    b"\x5d"
    b"\xc3"
)

PLACEHOLDER_HASH = 0xFEEDDEAD

REGISTER_SPACE_OFFSETS = {
    "rax": 0x0,
    "rcx": 0x8,
    "rdx": 0x10,
    "rbp": 0x28,
    "rsp": 0x20,
    "eax": 0x0,
    "ecx": 0x8,
    "edx": 0x10,
}

CUSTOM_SUM_MASKS = {
    b"\x55": b"\x50",
    b"\x48\x89\xe5": b"\x48\x89\xc0",
    b"\x89\x4d\x10": b"\x89\x40\x00",
    b"\x89\x55\x18": b"\x89\x40\x00",
    b"\x8b\x55\x10": b"\x8b\x40\x00",
    b"\x8b\x45\x18": b"\x8b\x40\x00",
    b"\x01\xd0": b"\x01\xc0",
    b"\x83\xc0\x0a": b"\x83\xc0\x00",
    b"\x5d": b"\x58",
    b"\xc3": b"\xc3",
    b"\x83\x7d\x10\x01": b"\x83\x78\x00\x00",
    b"\x75\x0d": b"\x75\x00",
    b"\xeb\x08": b"\xeb\x00",
}


def fnv1a64(data: bytes) -> int:
    """Compute the FNV-1a hash in 64 bit."""
    result = FNV1A64_INITIAL_STATE
    for b in data:
        result ^= b
        result = (result * FNV1A64_PRIME) % 2**64
    return result


if __name__ == "__main__":
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    full_data = b""
    specific_data = b""

    for instruction_index, instruction in enumerate(
        md.disasm(CUSTOM_SUM_BYTES, CUSTOM_SUM_ADDR)
    ):

        instruction_bytes = bytes(instruction.bytes)

        print(f"@0x{instruction.address:x}:{instruction.mnemonic} {instruction.op_str}")

        for index_operand, operand in enumerate(instruction.operands):
            full_update = (index_operand + 1) * 7777
            specific_update = (index_operand + 1) * 7777

            if operand.type == capstone.x86.X86_OP_REG:
                reg_name = instruction.reg_name(operand.value.reg)
                reg_addr = REGISTER_SPACE_OFFSETS[reg_name]
                full_update += (reg_addr + 7654321) * 98777
                specific_update += (reg_addr + 7654321) * 98777
                print(f"Register: {reg_name} @ 0x{reg_addr:x}")

            elif operand.type == capstone.x86.X86_OP_MEM:

                if instruction.reg_name(operand.value.mem.base) != 0:
                    reg_name = instruction.reg_name(operand.value.mem.base)
                    reg_addr = REGISTER_SPACE_OFFSETS[reg_name]
                    full_update += (reg_addr + 7654321) * 98777
                    specific_update += (reg_addr + 7654321) * 98777
                    print(f"Register: {reg_name} @ 0x{reg_addr:x}")

                if instruction.reg_name(operand.value.mem.index) not in (0, None):
                    reg_name = instruction.reg_name(operand.value.mem.index)
                    reg_addr = REGISTER_SPACE_OFFSETS[reg_name]
                    full_update += (reg_addr + 7654321) * 98777
                    specific_update += (reg_addr + 7654321) * 98777
                    print(f"Register: {reg_name} @ 0x{reg_addr:x}")

                if operand.value.mem.disp != 0:
                    full_update += PLACEHOLDER_HASH
                    specific_update += (operand.value.mem.disp + 1234567) * 67999
                    print(f"Scalar: 0x{operand.value.mem.disp:x}")

                if operand.value.mem.index > 1:
                    full_update += PLACEHOLDER_HASH
                    specific_update += (operand.value.mem.index + 1234567) * 67999
                    print(f"Scalar: 0x{operand.value.mem.index:x}")

            elif operand.type == capstone.x86.X86_OP_IMM:

                if capstone.x86.X86_GRP_JUMP in instruction.groups or capstone.x86.X86_GRP_CALL in instruction.groups:
                    full_update += PLACEHOLDER_HASH
                    specific_update += (PLACEHOLDER_HASH + 1234567) * 67999
                    print(f"Address: 0x{operand.value.imm:x}")

                else:
                    full_update += PLACEHOLDER_HASH
                    specific_update += (operand.value.imm + 1234567) * 67999
                    print(f"Scalar: 0x{operand.value.imm:x}")

            full_update %= 2**32
            specific_update %= 2**32

            full_data += full_update.to_bytes(4, "big")
            specific_data += specific_update.to_bytes(4, "big")

        full_data += CUSTOM_SUM_MASKS[instruction_bytes]
        specific_data += CUSTOM_SUM_MASKS[instruction_bytes]
        print()

    print(f"Full hash: 0x{fnv1a64(full_data):x}")
    print(f"Specific hash: 0x{fnv1a64(specific_data):x}")
```

-----

[^1]: The Ghidra implementation of 64-bit FNV-1a hashes is available in the [FNV1a64MessageDigest](https://github.com/NationalSecurityAgency/ghidra/blob/2517a3234822de74e05e642a55f79d8f3b4c5198/Ghidra/Framework/Generic/src/main/java/generic/hash/FNV1a64MessageDigest.java) class.

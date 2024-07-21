---
layout: "post"
title:  "Carving ELF files"
date:   "2024-07-21"
author: "Joren Vrancken"
lang: "en-US"
---

Recently, I created a simple tool, [Carve Exe](https://github.com/joren485/carve-exe), to carve executables from other files (e.g. memory dumps or network traffic). Carving executables from binary blobs is a common task in digital forensics and reverse engineering. For example, when analyzing how a malware sample unpacks and deobfuscates itself.

The problem of carving executables from binary blobs boils down to finding the beginning and the end of an executable file. Finding the beginning of an executable file is easy, as most file types have well-defined [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)[^0]. Determining the end of an executable file, given its beginning, is a bit harder, though. This blog discusses how to determine the (beginning and) end of an ELF executable, by computing its size by only looking at the headers in the file.

### The Layout of an ELF File
ELF executables consist of four parts:

1. The ELF file header,
2. The program headers table,
3. The section headers table,
4. The data sections.

#### The ELF File Header
Each ELF file starts with an ELF file header (52 bytes for 32-bit files and 64 bytes for 64-bit files). This header contains general information about the executable, such as the architecture and the entry point of the code.

The ELF file header structure is defined in the [elf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h) file from the Linux kernel:
<table>
<tr>
<th>32-bit</th>
<th>64-bit</th>
</tr>
<tr>
<td>
<pre>
typedef struct elf32_hdr {
  unsigned char	e_ident[EI_NIDENT];
  Elf32_Half	e_type;
  Elf32_Half	e_machine;
  Elf32_Word	e_version;
  Elf32_Addr	e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word	e_flags;
  Elf32_Half	e_ehsize;
  Elf32_Half	e_phentsize;
  Elf32_Half	e_phnum;
  Elf32_Half	e_shentsize;
  Elf32_Half	e_shnum;
  Elf32_Half	e_shstrndx;
} Elf32_Ehdr;
</pre>
</td>
<td>
<pre>
typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];
  Elf64_Half  e_type;
  Elf64_Half  e_machine;
  Elf64_Word  e_version;
  Elf64_Addr  e_entry;
  Elf64_Off   e_phoff;
  Elf64_Off   e_shoff;
  Elf64_Word  e_flags;
  Elf64_Half  e_ehsize;
  Elf64_Half  e_phentsize;
  Elf64_Half  e_phnum;
  Elf64_Half  e_shentsize;
  Elf64_Half  e_shnum;
  Elf64_Half  e_shstrndx;
} Elf64_Ehdr;
</pre>
</td>
</tr>
</table>

An ELF file always starts with `\x7F\x45\x4C\x46` (the first four bytes of `e_ident`), making it easy to identify.

To parse the other parts in the ELF file, we are interested in the following fields:
* Program headers table: Located at offset `e_phoff` with `e_phnum` entries, each of size `e_phentsize`.
* Section headers table: Located at offset `e_shoff` with `e_shnum` entries, each of size `e_shentsize`.

#### The Program Headers Table
The program headers table tells the operating system how to load the executable into memory. Each entry describes a _segment_. The header of each segment defines where the segment starts in the file, how big it is and how it should be loaded into memory.

As this blog focuses on data on disk, the contents of the program headers table are not relevant here.

<table>
<tr>
<th>32-bit</th>
<th>64-bit</th>
</tr>
<tr>
<td>
<pre>

typedef struct elf32_phdr {
  Elf32_Word	p_type;
  Elf32_Off	p_offset;
  Elf32_Addr	p_vaddr;
  Elf32_Addr	p_paddr;
  Elf32_Word	p_filesz;
  Elf32_Word	p_memsz;
  Elf32_Word	p_flags;
  Elf32_Word	p_align;
} Elf32_Phdr;
</pre>
</td>
<td>
<pre>
typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;
</pre>
</td>
</tr>
</table>

#### The Section Headers Table
The section headers table describes how the executable file’s data is stored. Each section contains specific data necessary for the executable, like code, constants, or debug information. The section header table defines their properties.

<table>
<tr>
<th>32-bit</th>
<th>64-bit</th>
</tr>
<tr>
<td>
<pre>
typedef struct elf32_shdr {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type;
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;
</pre>
</td>
<td>
<pre>
typedef struct elf64_shdr {
  Elf64_Word sh_name;
  Elf64_Word sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word sh_link;
  Elf64_Word sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
} Elf64_Shdr;
</pre>
</td>
</tr>
</table>


#### The Sections in an ELF File
The sections contain the actual data of the executable (e.g. the code and any static values). Their relevant properties are defined in the section headers table.

### Computing the Size of an ELF File
_Usually_, the layout of an ELF file is as follows:
1. The ELF file header,
2. The program header table,
3. The sections,
4. The section header table.

If this structure is followed, we can compute the file size by finding the end of the section headers table using the formula: `e_shoff` + `e_shentsize` * `e_shnum`. This formula gives us the size of the section header table from its offset plus its total size (number of entries times the size of each entry).

However, the ELF format does not enforce a strict order for its parts (except that the ELF file header must be at the start). The program header table, section header table, and sections can be in any order, as long as their pointers are correct. Thus, we need to find the end of the last part in the file to determine the file size.

We compute the end of each part using the following formulas:

1. The ELF file header end: `0x0 + e_ehsize`,
2. Program headers table end: `e_phoff + e_phnum * e_phentsize`
3. Each section's end: `sh_offset + sh_size`
4. Section headers table end: `e_shoff + e_shnum * e_shentsize`

The largest result among these will be the file size.

### Example Computation
Let's test this methodology on a real example: `/bin/ls`.

Using the [`readelf`](https://man7.org/linux/man-pages/man1/readelf.1.html) command, we can parse ELF files. First, let's look at the ELF file header:
```
$ readelf --file-header /bin/ls
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4f80
  Start of program headers:          64 (bytes into file)
  Start of section headers:          127936 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         28
  Section header string table index: 27
```

Using the values in the ELF file header, we compute the start, size and end of each header:

| **Header**                | **Offset start** | **# of entries** | **Entry size** | **Size**       | **Offset end**         |
|---------------------------|------------------|------------------|----------------|----------------|------------------------|
| **ELF File Header**       | 0                | 1                | 64             | 1 * 64 = 64    | 0 + 64 = 64            |
| **Program Headers Table** | 64               | 13               | 56             | 13 * 56 = 728  | 64 + 728 = 792         |
| **Section Headers Table** | 127936           | 28               | 64             | 28 * 64 = 1792 | 127936 + 1792 = 129728 |

We do the same for the sections, by parsing the section header table:
```
$ readelf --section-headers /bin/ls
There are 28 section headers, starting at offset 0x1f3c0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000000338  00000338
       0000000000000050  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000000388  00000388
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             00000000000003ac  000003ac
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000000003d0  000003d0
       0000000000000024  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000000003f8  000003f8
       0000000000000ac8  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           0000000000000ec0  00000ec0
       0000000000000561  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           0000000000001422  00001422
       00000000000000e6  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          0000000000001508  00001508
       00000000000000e0  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             00000000000015e8  000015e8
       0000000000000a68  0000000000000018   A       6     0     8
  [11] .relr.dyn         RELR             0000000000002050  00002050
       0000000000000050  0000000000000008   A       0     0     8
  [12] .init             PROGBITS         0000000000003000  00003000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .text             PROGBITS         0000000000003020  00003020
       0000000000012db3  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         0000000000015dd4  00015dd4
       000000000000000d  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         0000000000016000  00016000
       00000000000051a0  0000000000000000   A       0     0     32
  [16] .eh_frame_hdr     PROGBITS         000000000001b1a0  0001b1a0
       0000000000000594  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         000000000001b738  0001b738
       00000000000020f8  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       000000000001ef70  0001df70
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       000000000001ef78  0001df78
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .data.rel.ro      PROGBITS         000000000001ef80  0001df80
       0000000000000af8  0000000000000000  WA       0     0     32
  [21] .dynamic          DYNAMIC          000000000001fa78  0001ea78
       00000000000001f0  0000000000000010  WA       7     0     8
  [22] .got              PROGBITS         000000000001fc68  0001ec68
       0000000000000390  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000020000  0001f000
       0000000000000278  0000000000000000  WA       0     0     32
  [24] .bss              NOBITS           0000000000020280  0001f278
       00000000000012c0  0000000000000000  WA       0     0     32
  [25] .comment          PROGBITS         0000000000000000  0001f278
       000000000000001b  0000000000000001  MS       0     0     1
  [26] .gnu_debuglink    PROGBITS         0000000000000000  0001f294
       0000000000000010  0000000000000000           0     0     4
  [27] .shstrtab         STRTAB           0000000000000000  0001f2a4
       0000000000000119  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

Using the values in the section header table, we compute the start, size and end of each section:

| **Section** | **Section start offset** | **Section size** | **Offset end offset** |
|  | 0x0 | 0x0 | 0x0 + 0x0 = 0|
| .interp | 0x318 | 0x1c | 0x318 + 0x1c = 820|
| .note.gnu.property | 0x338 | 0x50 | 0x338 + 0x50 = 904|
| .note.gnu.build-id | 0x388 | 0x24 | 0x388 + 0x24 = 940|
| .note.ABI-tag | 0x3ac | 0x20 | 0x3ac + 0x20 = 972|
| .gnu.hash | 0x3d0 | 0x24 | 0x3d0 + 0x24 = 1012|
| .dynsym | 0x3f8 | 0xac8 | 0x3f8 + 0xac8 = 3776|
| .dynstr | 0xec0 | 0x561 | 0xec0 + 0x561 = 5153|
| .gnu.version | 0x1422 | 0xe6 | 0x1422 + 0xe6 = 5384|
| .gnu.version_r | 0x1508 | 0xe0 | 0x1508 + 0xe0 = 5608|
| .rela.dyn | 0x15e8 | 0xa68 | 0x15e8 + 0xa68 = 8272|
| .relr.dyn | 0x2050 | 0x50 | 0x2050 + 0x50 = 8352|
| .init | 0x3000 | 0x1b | 0x3000 + 0x1b = 12315|
| .text | 0x3020 | 0x12db3 | 0x3020 + 0x12db3 = 89555|
| .fini | 0x15dd4 | 0xd | 0x15dd4 + 0xd = 89569|
| .rodata | 0x16000 | 0x51a0 | 0x16000 + 0x51a0 = 111008|
| .eh_frame_hdr | 0x1b1a0 | 0x594 | 0x1b1a0 + 0x594 = 112436|
| .eh_frame | 0x1b738 | 0x20f8 | 0x1b738 + 0x20f8 = 120880|
| .init_array | 0x1df70 | 0x8 | 0x1df70 + 0x8 = 122744|
| .fini_array | 0x1df78 | 0x8 | 0x1df78 + 0x8 = 122752|
| .data.rel.ro | 0x1df80 | 0xaf8 | 0x1df80 + 0xaf8 = 125560|
| .dynamic | 0x1ea78 | 0x1f0 | 0x1ea78 + 0x1f0 = 126056|
| .got | 0x1ec68 | 0x390 | 0x1ec68 + 0x390 = 126968|
| .data | 0x1f000 | 0x278 | 0x1f000 + 0x278 = 127608|
| .bss (`NOBITS`) | 0 | 0 | 0 + 0 = 0 |
| .comment | 0x1f278 | 0x1b | 0x1f278 + 0x1b = 127635|
| .gnu_debuglink | 0x1f294 | 0x10 | 0x1f294 + 0x10 = 127652|
| .shstrtab | 0x1f2a4 | 0x119 | 0x1f2a4 + 0x119 = 127933|

Now we have the start, size and end of all headers and all sections, we can simply compute the file size by getting the largest offset:

```bash
$ python
>>> max([64, 792, 129728, 0, 820, 904, 940, 972, 1012, 3776, 5153, 5384, 5608, 8272, 8352, 12315, 89555, 89569, 111008, 112436, 120880, 122744, 122752, 125560, 126056, 126968, 127608, 0, 127635, 127652, 127933])
129728
```

The section header table is apparently the last part of `/bin/ls`, and as such, its end (at offset 129728) should be equal to the file size.

Let's check our answer:
```bash
$ ls -l /bin/ls
-rwxr-xr-x 1 root root 129728 28 mrt 20:09 /bin/ls
```

It works!


### Discussion
In this post, we discussed carving ELF files from other files/data streams (e.g. memory dumps and network traffic). Finding the beginning of an ELF file is simple, just look for the magic bytes `\x7F\x45\x4C\x46`, but the end of the file does not have such a marker. In this post, we saw that it is possible to determine the end of an ELF file (giving its beginning), by parsing the file and computing which part of the file is the last.

It should be noted that the headers in an ELF file do not have to contain the correct values for the ELF file to work. For example, the section header table is completely ignored during loading and execution of an ELF file. If the section header table were to contain bad values (e.g. wrong offsets or wrong section sizes), the ELF file would execute just fine, but linking against the file would not work. Such bad values would also make the analysis in this post impossible. Similarly, if the ELF file has some sort of appended overlay that is not properly part of a section, these types of analyzes will not work. Garbage in, garbage out.

---

[^0]: `\x4D\x5A` (the MZ header) for Windows DOS executables files and `\x7F\x45\x4C\x46` (the ELF header) for Linux ELF files.
[^1]: We should skip any section of type `NOBITS`, as these sections do not have any bytes on disk.

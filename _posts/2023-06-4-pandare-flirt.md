---
layout: "post"
title:  "Using PANDA to search for F.L.I.R.T. signatures during process execution"
date:   "2023-06-04"
author: "Joren Vrancken"
lang: "en-US"
---

When a malware analyst gets a new malware sample to analyze, one of the first questions they might have, is what functions are called during the execution of the sample. To solve this problem, we can use any old debugger to walk through the sample manually, but we can also automate and record our analysis with a dynamic analysis framework like [PANDA](https://panda.re/).

To showcase PANDA, and learn how to use it along the way, we will tackle the problem of automatically identifying functions during process execution in this blog post.

### What is PANDA?
The Platform for Architecture-Neutral Dynamic Analysis (PANDA) is a reverse engineering dynamic analysis framework that emulates a whole system (with [QEMU](https://www.qemu.org/)), recording every step of the execution (i.e. every instruction and memory change). These recordings can later be replayed, to rerun and analyze an executable in the same exact way as the original execution.

Analyzing recordings instead of actual processes has multiple advantages:
1. Deterministic analysis: Every time you replay a recording, you will have access to the same exact environment (e.g. memory and registry values).

2. Performing complex analyzes: During the live execution of a process, any analysis is often limited, because the process likely relies on external resources that might time out or otherwise change (e.g. network connections and other processes). When analyzing a replay, we do not have this problem, as the execution is pre-defined. This allows us to perform complex, time-consuming or performance heavy analyses of the process execution. For example, [the creators of PANDA wrote a plugin](https://www.youtube.com/watch?v=2HQqZZNC4P8) that calculates the entropy of the full memory space of a process, on the execution of every basic block to find unpacked malware.

PANDA provides callbacks to different low-level events (e.g. the execution of instructions and memory writes), that we can use to analyze moments of interest during the process execution. For example, the following Python function will be called every time data is written to memory:
```python
@panda.cb_virt_mem_after_write
def virt_mem_after_write(env, pc, address, size, buffer):
    """
    Prints how many bytes were written to a specific address.

    :param env: The current state during the execution.
    :param pc: The current program counter.
    :param address: The address where data was written to.
    :param size: The size of the written data.
    :param buffer: The written data.
    """
    print(f"@{hex(pc)}: {size} bytes were written to {hex(address)}.")
```

### Detecting Functions in PANDA
To identify functions in a process, we have to first find where functions start. We can accomplish this with PANDA, by looking for function calls (i.e. `CALL` instruction being executed).

We could use the `cb_insn_exec` callback (called before the execution of each instruction), to look at every instruction and perform further analysis when we find a `CALL` instruction. However, PANDA provides plugins that implement common functionality. For example, the [`callstack_instr`](https://github.com/panda-re/panda/tree/dev/panda/plugins/callstack_instr) tracks function calls and provides callbacks for function calls and function call returns. For example, the following Python function will be called every time a function is called during the process execution:

```python
@panda.ppp("callstack_instr", "on_call")
def on_call(env, addr_callee):
    """Print every function call."""
    current_program_counter = panda.arch.get_pc(env)
    print(f"@{hex(current_program_counter)}: Call to {hex(addr_callee)}.")
```

As PANDA emulates a whole system, it will record every instruction of every process running during the recording, including the processes that are not relevant to us. To make sure we only analyze function calls that are directly relevant to us, we can skip any processes that are not of interest to us:

 ```python
@panda.ppp("callstack_instr", "on_call")
def on_call(env, addr_callee):
    """Print every function call in 'our-program'."""
    if panda.get_process_name(env) != "our-program":
        return

    current_program_counter = panda.arch.get_pc(env)
    print(f"@{hex(current_program_counter)}: Call to {hex(addr_callee)}.")
```

This allows us to find all function calls made during the execution of our process of interest. However, this only tells us that _a function_ is being called, not which function.

### Identifying Functions using F.L.I.R.T. Signatures.
We need a way to identify these functions. Identifying functions in executable binaries is a hard but common problem in reversing engineering. Most reverse engineering suites (e.g. IDA Pro, Ghidra and Binary Ninja) use a combination of byte pattern matching and control flow heuristics. In essence, they use the following approach:
1. Take a popular library (e.g. libc).
2. Compile it with symbols.
3. Create a pattern for each function in the compiled files.
4. Search for these patterns in other binaries.
5. If we find a pattern match, we have identified a function.

IDA Pro, the most popular disassembler and decompiler, uses [F.L.I.R.T.](https://hex-rays.com/products/ida/tech/flirt/in_depth/) signatures. IDA Pro comes with a number of pre-generated signatures for popular libraries, and it also provides tooling to generate your own signatures that we can use to create signatures for testing.

#### Creating F.L.I.R.T. Signatures

To test PANDA, we will need a test binary. We take a basic program in [Nim](https://nim-lang.org/):
```nim
# hello.nim

proc main(greeting: string) =
    echo greeting

main("Hello World.")
```

We compile `hello.nim`, and strip it of all symbols for good measure:
```shell
$ nim c -d:release --opt:size --os:linux -o:hello --passL:-static hello.nim
$ strip --strip-all -o hello-stripped hello
```

**_Note:_** _We statically link the program to make sure it will run in the PANDA QEMU virtual machine. As PANDA relies on QEMU, it is important to choose a virtual machine with an OS that the binary can run on. For example, if we dynamically linked the binary and ran it in a QEMU virtual machine with a different libc version, the binary will not start._

This gives us two binaries, `hello` (with symbols) and `hello-stripped` (without symbols):
```shell
$ ./hello
Hello World.
$ ./hello-stripped
Hello World.
$ nm hello-stripped
nm: hello-stripped: no symbols
```

Next, we generate signatures based on the object files created during compilation[^1] of `hello`:
```shell
$ ar -rcs hello.a ~/.cache/nim/*/*.o
$ pelf hello.a hello.pat
$ sigmake hello.pat hello.sig
```
#### Verifying the F.L.I.R.T. Signatures
Before we can use the signatures, we should first verify that we can actually use them to identify functions in the `hello` and `hello-stripped` binaries.

The simplest way to do this, is to iterate over the file byte by byte to see if we match a signature somewhere in the file (i.e. search for the byte pattern in the file). The following Python script trivially implements this by iterating over every chunk of 256[^2] bytes in `hello-stripped`, and checks whether the chunk matches any of the generated signatures.

We use [`python-flirt`](https://github.com/williballenthin/lancelot/tree/master/pyflirt) to handle the actual F.L.I.R.T. signature matching logic.

```python
import flirt

with open("hello.sig", "rb") as h_file:
    data_sig = h_file.read()

signatures = flirt.parse_sig(data_sig)

matcher: flirt.FlirtMatcher = flirt.compile(signatures)

with open("hello-stripped", "rb") as h_file:
    data_file = h_file.read()

for i in range(len(data_file)):
    chunk = data_file[i: i + 0x100]
    for match in matcher.match(chunk):
        for function_name, _, offset in match.names:
            function_address = i + offset
            print(f"@{hex(function_address)}: {function_name}")
```

Our script gives us the following output (truncated), listing at which address a function was found:
```
...
@0x536c: PreMainInner
@0x5371: main__hello_1
@0x53c0: PreMain
@0x5414: NimMain
@0x5465: NimMainModule
@0x5475: NimMainInner
```

And where are these functions actually located in the binary? Let's look at the symbol table of `hello`:
```shell
$ nm hello | egrep "PreMainInner|main__hello_1|PreMain|NimMain"
0000000000405371 T main__hello_1
0000000000405414 T NimMain
0000000000405475 T NimMainInner
0000000000405465 T NimMainModule
00000000004053c0 T PreMain
000000000040536c T PreMainInner
```

Great! As we can see, the addresses of the functions identified by our script match[^3] those of the symbols in `hello`.


<!--
Examples that show that performance is not an important factor:
* https://moyix.blogspot.com/2014/07/breaking-spotify-drm-with-panda.html
* https://www.youtube.com/watch?v=2HQqZZNC4P8
-->

### Creating Recordings with PANDA
At this point, we should have everything to identify functions in processes, but we do still need a recording of a process. PANDA provides multiple ways to make recordings. We could do it manually from the QEMU Monitor (a command line for QEMU) or do it programmatically using Python code:

```python
panda = Panda(generic="x86_64")
command = "/data/binaries/hello-stripped"

@panda.queue_blocking()
def take_recording():
    panda.revert_sync("root")
    panda.copy_to_guest("/data/binaries/", absolute_paths=True)

    print(f"Testing command: '{command}'")
    command_output = panda.run_serial_cmd(command)
    print(f"Output: '{command_output}'")

    panda.record_cmd(command, recording_name="/data/recordings/hello-stripped", snap_name=None)

    panda.end_analysis()

panda.run()
```

This Python code does the following:
1. Create a `Panda` instance: This creates the virtual machine. We can either specify our own image or use one of [the pre-built images](https://panda.re/qcows/). In our code, we use the default x86-64 Linux image.
2. Define a function that will run after the virtual machine has started. This function:
    1. `panda.revert_sync`: Reverts the virtual machine to it original state.
    2. `panda.copy_to_guest`: Copy our binary into the virtual machine.
    3. `panda.record_cmd`: Start recording, run the binary and stop recording.
3. `panda.run()`: Start the virtual machine and run the function.

### Setting Up an Analysis Environment in Docker
Now that we have all the code we need, it is finally time to actually do something! PANDA is a complex system with specific dependencies (e.g. `copy_to_guest` needs the `genisoimage` utility). To make sure we use an environment with PANDA and its dependencies properly installed, we run our analysis in [the Docker image provided by PANDA](https://hub.docker.com/r/pandare/panda)[^4].

To correctly set up all necessary files, we use the following Docker Compose configuration:

```yaml
services:
  panda:
    image: "pandare/panda"
    working_dir: "/data/"
    command: bash -c "python -m pip install --no-cache-dir python-flirt && python /data/run.py"
    volumes:
      - "${PWD}/binaries/hello-stripped:/data/binaries/hello-stripped"
      - "${PWD}/recordings/:/data/recordings/"
      - "${PWD}/signatures/:/data/signatures/"
      - "${PWD}/run.py:/data/run.py"

      # Qcow2 images cache
      - "${PWD}/images/:/root/.panda/"
```

**_Note:_** _`command` is used to install `python-flirt` when the Docker container is started. In an actual production environment, we would, of course, create a new image with all the necessary dependencies._

When we run the container, the output tells us that PANDA has successfully created a recording (this took ~6 seconds):
```
PANDA[core]:os_familyno=2 bits=64 os_details=ubuntu:4.15.0-72-generic-noaslr-nokaslr
writing snapshot:	/data/recordings/hello-stripped_x86_64-rr-snp
opening nondet log for write:	/data/recordings/hello-stripped_x86_64-rr-nondet.log
Finalizing the recording
...complete!
using generic x86_64
os_name=[linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr]
[PYPANDA] Panda args: [/usr/local/lib/python3.8/dist-packages/pandare/data/x86_64-softmmu/libpanda-x86_64.so -L /usr/local/lib/python3.8/dist-packages/pandare/data/pc-bios /root/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2 -display none -m 1024 -serial unix:/tmp/pypanda_srtxuwa0s,server,nowait -monitor unix:/tmp/pypanda_m6r7aqhjp,server,nowait]
Taking recording
Testing command: '/data/binaries/hello-stripped'
Output: 'Hello World.'
Finished recording
```

Besides the PANDA output, we also see the output of our script (i.e. `Output: 'Hello World.'`).

PANDA created a recording in the `recordings` directory:
```shell
$ ls -hl recordings
total 292M
-rw-r--r-- 1 root root  19K 30 may 21:33 hello-stripped_x86_64-rr-nondet.log
-rw-r----- 1 root root 292M 30 may 21:33 hello-stripped_x86_64-rr-snp
```

The `-rr-snp` file is a snapshot of the virtual machine and the `-rr-nondet.log` file contains all steps taking during the recording. When PANDA replays this recording, it reverts the virtual machine to the snapshot and replays all the steps in the `-rr-nondet.log` file.

### Putting Everything Together
We know how to use PANDA to analyze function calls, how to identify functions with F.L.I.R.T. signatures, and we have set up our analysis environment (i.e. a Docker container) with a recording. Everything is ready for our analysis!

In short, our analysis consists of the following steps:
1. Use PANDA to record a running binary:
    1. Start a QEMU virtual machine.
    2. Start recording.
    3. Run the binary.
    4. Stop recording and stop the virtual machine.
2. Enable a callback on each function call.
3. Replay the recording.
4. For each function call:
    1. Read 256 bytes of the callee.
    2. Check if the bytes match an F.L.I.R.T. signature.
    3. Print any matches.

_The final code is available as [an example in the PANDA GitHub repository](https://github.com/panda-re/panda/tree/82334a57cce6792f22348a4d07e6fc706c529423/panda/python/examples/flirt-signatures)._

Besides printing the identified functions, this code also disassembles and prints the first 5 instructions of each function, to verify the identified functions actually match the instructions in the original binary.

Our script gives the following output (truncated):
```
...
@0x401709: 'main'
	0x401709	endbr64
	0x40170d	push	rax
	0x40170e	mov	qword ptr [rip + 0xb787b], rdx
	0x401715	mov	qword ptr [rip + 0xb787c], rsi
	0x40171c	mov	dword ptr [rip + 0xb787e], edi
...
@0x405371: 'main__hello_1'
	0x405371	endbr64
	0x405375	sub	rsp, 0x18
	0x405379	mov	rax, qword ptr fs:[0x28]
	0x405382	mov	qword ptr [rsp + 8], rax
	0x405387	xor	eax, eax

@0x4053c0: 'PreMain'
	0x4053c0	endbr64
	0x4053c4	sub	rsp, 0x18
	0x4053c8	mov	rax, qword ptr fs:[0x28]
	0x4053d1	mov	qword ptr [rsp + 8], rax
	0x4053d6	lea	rax, [rip - 0x71]
...
```

A full match with the functions in the original `hello` binary:
```shell
$ objdump -D -Mintel hello
...
0000000000401709 <main>:
  401709:       f3 0f 1e fa             endbr64
  40170d:       50                      push   rax
  40170e:       48 89 15 7b 78 0b 00    mov    QWORD PTR [rip+0xb787b],rdx
  401715:       48 89 35 7c 78 0b 00    mov    QWORD PTR [rip+0xb787c],rsi
  40171c:       89 3d 7e 78 0b 00       mov    DWORD PTR [rip+0xb787e],edi
...
00000000004053c0 <PreMain>:
  4053c0:       f3 0f 1e fa             endbr64
  4053c4:       48 83 ec 18             sub    rsp,0x18
  4053c8:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  4053cf:       00 00
  4053d1:       48 89 44 24 08          mov    QWORD PTR [rsp+0x8],rax
  4053d6:       48 8d 05 8f ff ff ff    lea    rax,[rip+0xffffffffffffff8f]
...
0000000000405371 <main__hello_1>:
  405371:       f3 0f 1e fa             endbr64
  405375:       48 83 ec 18             sub    rsp,0x18
  405379:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  405380:       00 00
  405382:       48 89 44 24 08          mov    QWORD PTR [rsp+0x8],rax
  405387:       31 c0                   xor    eax,eax
...
```

### Discussion

It took some setup, but in the end, we successfully created a simple sandbox environment to identify functions in a running process.

I really like the approach PANDA brings to dynamic analysis. The most important contribution that PANDA makes is, in my opinion, the ability to make deterministic recordings. This simplifies complex analyses by not having to deal with changing environments (e.g. new memory address space) every time we run a binary. It is also great for collaboration between multiple analysts, as they can all work on the same recording simultaneously.

PANDA focuses on dynamic analysis through code (in contrast to stepping through a process in a debugger, manually). This approach comes with the upfront cost of writing code and setting up Docker containers, but it comes with the benefit of forcing us to automate our analysis. For example, in this post, we created a simple sandbox that can be repurposed for other binaries.

The use of Docker adds an extra layer of abstraction and complexity, but it also allows us to apply DevOps paradigms to dynamic analysis. For example, by creating dynamic analysis pipelines that can handle a large-scale of samples.

When manually debugging a binary (e.g. in x64dbg), the main question of an analyst is often "Where am I in the execution of the program?". Using PANDA, the question changes to "How can I predefine callbacks for the behavior I am trying to analyze?". This is a different mindset, with positive and negative sides. A negative is that it is harder to understand where we are in the execution of the program (this is why I got the idea of matching function calls with F.L.I.R.T. signatures).

However, there is a lot of work to do to get PANDA to point where it can be deployed at scale. Because PANDA relies heavily on the QEMU images, there needs to be a large library of supported QEMU images. Windows-support also needs to be improved. The highest supported Windows version is 64-bit Windows 7 and many plugins only support Linux.

In my opinion, we need more frameworks that focus on debugging through code, like PANDA. As there is an endless stream of malware samples, it is crucial to create tooling that can automate malware analyzes.

----

[^1]: Creating F.L.I.R.T. signatures based on Nim executables is discussed in detail in the [Pwn2Win CTF 2016 Suspect Router](https://github.com/epicleet/write-ups-2016/tree/pwn2win-ctf-2016/pwn2win-ctf-2016/reverse/suspect-router-100) write-up.

[^2]: 256 bytes is an arbitrary value that should be large enough to always cover the 32 + n bytes needed by the F.L.I.R.T. signatures.

[^3]: `nm` adds 0x400000 to show the virtual address of the functions, instead of the actual offset within the file.

[^4]: Consequently, the QEMU virtual machine is run inside a Docker container.

# GadgetSniper



A precision tool for hunting **call-stack spoofing gadgets** inside 64-bit Windows DLLs.



GadgetSniper scans PE32+ binaries for instruction sequences of the form `call X ; jmp qword ptr [non-volatile-reg]`, the exact primitive needed to build believable spoofed call stacks. Rather than grepping raw byte patterns and hoping for the best, it leans on [Iced](https://github.com/icedland/iced) (a production-grade x86/x64 disassembler/decoder) to validate every candidate instruction, which eliminates the false positives that come with simple signature matching against variable-length x64 encodings.



## Why This Matters



Call-stack spoofing is one of the more interesting evasion techniques in the current landscape. A spoofed stack needs real `call ; jmp [reg]` gadgets that live inside legitimate, signed DLLs so the resulting frames look clean to any stack-walking logic. Finding those gadgets manually is tedious; finding them at scale across an entire System32 is worse.



GadgetSniper automates that hunt with two properties that set it apart:



- **Real disassembly, not byte matching.** x64 instructions are variable-length and overlap constantly. A raw byte scan will match inside immediates, displacement fields, and multi-byte prefixes, producing phantom gadgets that don't actually decode as the instruction you think they are. GadgetSniper feeds every candidate through Iced's decoder and only keeps results where the instruction decodes cleanly, is actually a `call`, and consumes exactly the right number of bytes with no trailing junk.



- **Focused on what matters.** The default gadget set targets `jmp qword ptr [reg]` for each of the callee-saved (non-volatile) registers: RBX, RBP, RSI, RDI, R12, R13, R14, R15. These are the registers that survive across function calls and are therefore the ones an attacker (or a red-team operator validating defenses) actually needs for frame fabrication. The tool handles all the x64 encoding edge cases: REX.B prefixes for extended registers, the `[rbp+0]` / `[r13+0]` zero-displacement forms forced by ModRM constraints, and the shared opcodes between RSI/R14 and RDI/R15 that are only disambiguated by the REX prefix.



## Features



- Iced-backed instruction decoding for zero false-positive gadget discovery

- Parallel DLL scanning with per-file error isolation (one bad file never kills the run)

- Recursive directory walking that skips access-denied folders and avoids symlink/junction cycles

- Structured text report with summary statistics, per-type gadget counts, and per-file detail

- Scans all executable sections, not just `.text`



## Installation



### Prerequisites



- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8) (or later)



### Setup



Clone the repository and restore the Iced dependency:



```bash

git clone https://github.com/ZakiPedio/GadgetSniper.git

cd GadgetSniper

dotnet restore

```



If you need to install the package (but it should be already referenced in the `.csproj`):



```bash

dotnet add package Iced

```



### Build



Standard build:



```bash

dotnet build -c Release

```



Self-contained single-file executable (no .NET runtime required on the target host):



```bash

dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true

```



The resulting binary will be in `bin/Release/net8.0/win-x64/publish/`.



## Usage



```

GadgetSniper <directory> [--recursive] [--output <file>]

```



| Flag | Description |

|------|-------------|

| `<directory>` | Path to the folder containing DLLs to scan |

| `--recursive`, `-r` | Recurse into subdirectories |

| `--output`, `-o` | Output report path (default: `gadget-report.txt`) |



### Examples



Scan a single directory:



```

GadgetSniper.exe C:\Windows\System32\example.dll

```



Recursive scan with custom output:



```

GadgetSniper.exe C:\Windows\System32 --recursive --output sys32-gadgets.txt

```



### Sample Output



```

|-> C:\Windows\System32\example.dll

|--> Found 2 gadget(s)

|---> jmp qword ptr [rbx] @ 0x7FFB1A2C3D40  <-  call qword ptr [rax+10h] @ 0x7FFB1A2C3D3A

|---> jmp qword ptr [r14] @ 0x7FFB1A2E8F10  <-  call rbp @ 0x7FFB1A2E8F0E

```



The generated report includes a summary header with total gadget counts broken down by type, followed by the full per-file detail.



## How It Works



1. **PE parsing**: reads the DOS/NT headers and section table directly from the raw bytes (no P/Invoke, no managed PE loader). Only PE32+ (64-bit) images are processed.

2. **Section scan**: iterates every executable section byte-by-byte, matching against the known `jmp qword ptr [reg]` encodings for all eight non-volatile registers, accounting for REX prefixes and ModRM/SIB edge cases.

3. **Call validation**: for each matched jump, walks backward up to 16 bytes and tries to decode a `call` instruction using Iced. Only candidates that decode as a valid `call` consuming exactly the bytes between the candidate start and the jump are accepted.

4. **Deduplication and reporting**: results are deduplicated by (gadget VA, call VA) pair and written to a structured report.



## Special Thanks



Thanks to [rastamouse](https://github.com/rasta-mouse) and [GadgetHunter](https://github.com/rasta-mouse/GadgetHunter) for the inspiration behind this project.


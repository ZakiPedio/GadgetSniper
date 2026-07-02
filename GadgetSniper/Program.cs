using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Iced.Intel;

namespace GadgetHunter;

internal static class Program
{
    // PE constants (winnt.h names kept so they're greppable against the spec)
    private const ushort ImageDosSignature = 0x5A4D;       // "MZ"
    private const uint ImageNtSignature = 0x00004550;   // "PE\0\0"
    private const ushort ImageNtOptional64 = 0x20B;        // PE32+
    private const uint ImageScnMemExecute = 0x20000000;   // IMAGE_SCN_MEM_EXECUTE
    private const int SectionHeaderSize = 40;           // IMAGE_SIZEOF_SECTION_HEADER

    // jmp qword ptr [reg] (opcode FF /4) for the callee-saved registers:
    //   RBX, RBP, RDI, RSI, R12, R13, R14, R15.
    //
    // Encoding gotchas this table accounts for:
    //  - rbx/rsi/rdi need no prefix.
    //  - [rbp] / [r13] can't be encoded with mod=00 (rm=101 means RIP-relative),
    //    so the zero-displacement form is used: FF 65 00  ([rbp+0]).
    //  - r12-r15 require a REX.B prefix (0x41); r12 also needs a SIB byte (24).
    //  - FF 26 / FF 27 are shared by rsi/rdi AND r14/r15 - the REX.B prefix is
    //    the only thing that distinguishes them, so each pattern explicitly
    //    requires (or forbids) a preceding 0x41.
    private static readonly JmpPattern[] Patterns =
    {
        new("jmp qword ptr [rbx]", false, new byte[] { 0xFF, 0x23 }),
        new("jmp qword ptr [rbp]", false, new byte[] { 0xFF, 0x65, 0x00 }),
        new("jmp qword ptr [rsi]", false, new byte[] { 0xFF, 0x26 }),
        new("jmp qword ptr [rdi]", false, new byte[] { 0xFF, 0x27 }),
        new("jmp qword ptr [r12]", true,  new byte[] { 0xFF, 0x24, 0x24 }),
        new("jmp qword ptr [r13]", true,  new byte[] { 0xFF, 0x65, 0x00 }),
        new("jmp qword ptr [r14]", true,  new byte[] { 0xFF, 0x26 }),
        new("jmp qword ptr [r15]", true,  new byte[] { 0xFF, 0x27 }),
    };

    public static int Main(string[] args)
    {
        // --- argument parsing ---
        var dir = "";
        var outputPath = "gadget-report.txt";
        var recursive = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--recursive":
                case "-r":
                    recursive = true;
                    break;
                case "--output":
                case "-o":
                    if (i + 1 >= args.Length)
                    {
                        Console.Error.WriteLine("Error: --output requires a file path.");
                        return 1;
                    }
                    outputPath = args[++i];
                    break;
                default:
                    if (dir.Length == 0)
                        dir = args[i];
                    break;
            }
        }

        if (dir.Length == 0)
        {
            Console.Error.WriteLine("Usage: GadgetHunter <directory> [--recursive] [--output <file>]");
            return 1;
        }

        if (!Directory.Exists(dir))
        {
            Console.Error.WriteLine($"Error: Directory not found: {dir}");
            return 1;
        }

        // Walk the tree ourselves. A single Directory.GetFiles(..., AllDirectories)
        // aborts the whole enumeration the first time it hits a folder it can't
        // read (e.g. C:\Windows\System32\config), so we recurse manually and skip
        // any directory we can't access instead of letting it kill the run.
        var dlls = EnumerateDlls(dir, recursive).ToArray();

        if (dlls.Length == 0)
        {
            Console.Error.WriteLine("No DLLs found in directory.");
            return 0;
        }

        // Each file is independent, so analyse them in parallel. Findings are
        // printed live (under a lock so a file's lines stay together) the moment
        // they're discovered, and also stored by index for the final report.
        var results = new FileResult[dlls.Length];
        var consoleLock = new object();

        Parallel.For(0, dlls.Length, i =>
        {
            FileResult result;
            try
            {
                result = ProcessDll(dlls[i]);
            }
            catch (Exception ex)
            {
                // Don't let one bad file kill the run, but don't swallow the
                // reason either - surface it on stderr.
                result = new FileResult(dlls[i], new List<Gadget>(), ex.Message);
            }

            results[i] = result;
            PrintResult(result, consoleLock); // live, as soon as it's found
        });

        // Write the report (summary first, then the per-file detail) and tell
        // the user where it landed.
        try
        {
            var fullOut = Path.GetFullPath(outputPath);
            WriteReport(fullOut, dir, recursive, results);
            Console.WriteLine();
            Console.WriteLine($"Report saved to {fullOut}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: could not write report to '{outputPath}': {ex.Message}");
            return 1;
        }

        return 0;
    }

    // Prints a single file's result immediately. The lock keeps one file's lines
    // contiguous even though several threads may be finishing at once.
    private static void PrintResult(FileResult result, object consoleLock)
    {
        if (string.IsNullOrEmpty(result.Error) && result.Gadgets.Count == 0)
            return; // nothing interesting to say about this one

        lock (consoleLock)
        {
            if (!string.IsNullOrEmpty(result.Error))
            {
                Console.Error.WriteLine($"|-> {result.Path}");
                Console.Error.WriteLine($"|--> skipped: {result.Error}");
                return;
            }

            Console.WriteLine();
            Console.WriteLine($"|-> {result.Path}");
            Console.WriteLine($"|--> Found {result.Gadgets.Count} gadget(s)");
            foreach (var g in result.Gadgets)
                Console.WriteLine($"|---> {g.Name} @ 0x{g.GadgetVa:X}  <-  {g.CallText} @ 0x{g.CallVa:X}");
        }
    }

    // Builds the report: a summary block on the first lines, then the detailed
    // findings (ordered by path for determinism), then anything that was skipped.
    private static void WriteReport(string outputPath, string root, bool recursive, FileResult[] results)
    {
        var skipped = results.Where(r => !string.IsNullOrEmpty(r.Error))
                                .OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
        var withGadgets = results.Where(r => string.IsNullOrEmpty(r.Error) && r.Gadgets.Count > 0)
                                 .OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();

        var totalGadgets = withGadgets.Sum(r => r.Gadgets.Count);
        var byType = withGadgets.SelectMany(r => r.Gadgets)
                                .GroupBy(g => g.Name)
                                .OrderByDescending(grp => grp.Count())
                                .ThenBy(grp => grp.Key, StringComparer.Ordinal)
                                .ToList();

        var sb = new StringBuilder();

        // --- summary (first lines) ---
        sb.AppendLine("==================== GadgetHunter Report ====================");
        sb.AppendLine($"Generated      : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Scanned        : {root}{(recursive ? "  (recursive)" : "")}");
        sb.AppendLine($"DLLs examined  : {results.Length}");
        sb.AppendLine($"  with gadgets : {withGadgets.Count}");
        sb.AppendLine($"  skipped      : {skipped.Count}");
        sb.AppendLine($"Total gadgets  : {totalGadgets}");
        if (byType.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Gadgets by type:");
            foreach (var grp in byType)
                sb.AppendLine($"  {grp.Key,-24} : {grp.Count()}");
        }
        sb.AppendLine("=============================================================");
        sb.AppendLine();

        // --- detailed findings ---
        if (withGadgets.Count == 0)
        {
            sb.AppendLine("No gadgets found.");
        }
        else
        {
            foreach (var result in withGadgets)
            {
                sb.AppendLine($"|-> {result.Path}");
                sb.AppendLine($"|--> Found {result.Gadgets.Count} gadget(s)");
                foreach (var g in result.Gadgets)
                    sb.AppendLine($"|---> {g.Name} @ 0x{g.GadgetVa:X}  <-  {g.CallText} @ 0x{g.CallVa:X}");
                sb.AppendLine();
            }
        }

        // --- skipped files (so the report is self-contained) ---
        if (skipped.Count > 0)
        {
            sb.AppendLine("---- Skipped files ----");
            foreach (var result in skipped)
                sb.AppendLine($"{result.Path}  ({result.Error})");
        }

        File.WriteAllText(outputPath, sb.ToString());
    }

    // Depth-first walk that skips directories we can't enumerate (access denied,
    // vanished mid-walk, I/O error) rather than aborting. Reparse points
    // (junctions / symlinks) are not followed, which avoids cycles and prevents
    // wandering out of the intended tree.
    private static IEnumerable<string> EnumerateDlls(string root, bool recursive)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.dll");
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            catch (IOException) { continue; }

            // yield is outside the try above (can't yield from a try/catch).
            foreach (var f in files)
                yield return f;

            if (!recursive)
                continue;

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subdirs)
            {
                try
                {
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0)
                        continue; // don't follow junctions/symlinks
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                stack.Push(sub);
            }
        }
    }

    private static FileResult ProcessDll(string path)
    {
        var data = File.ReadAllBytes(path);
        var gadgets = new List<Gadget>();

        // --- DOS / NT header sanity, all bounds-checked with 64-bit math so a
        //     garbage e_lfanew can't wrap a uint and slip past a guard. ---
        if (data.Length < 0x100 || ReadUInt16(data, 0) != ImageDosSignature)
            return new FileResult(path, gadgets, "");

        var eLfanew = ReadUInt32(data, 0x3C);
        if (!CanRead(data, eLfanew, 24) || ReadUInt32(data, eLfanew) != ImageNtSignature)
            return new FileResult(path, gadgets, "");

        var numSections = ReadUInt16(data, eLfanew + 6);
        var optHeaderSize = ReadUInt16(data, eLfanew + 20);
        var optHeaderOffset = eLfanew + 24u;
        if (!CanRead(data, optHeaderOffset, optHeaderSize))
            return new FileResult(path, gadgets, "");

        // jmp qword ptr [reg] and the R8-R15 registers only exist in 64-bit
        // code, so anything that isn't PE32+ has nothing for us to find.
        if (ReadUInt16(data, optHeaderOffset) != ImageNtOptional64)
            return new FileResult(path, gadgets, "not a 64-bit (PE32+) image");

        var imageBase = ReadUInt64(data, optHeaderOffset + 24);
        var secHdrOffset = optHeaderOffset + optHeaderSize;

        var sections = new List<SectionInfo>(numSections);
        for (var i = 0; i < numSections; i++)
        {
            var off = secHdrOffset + (uint)(i * SectionHeaderSize);
            if (!CanRead(data, off, SectionHeaderSize))
                break;

            sections.Add(new SectionInfo(
                name: ReadAsciiString(data, off, 8),
                virtSize: ReadUInt32(data, off + 8),
                virtAddr: ReadUInt32(data, off + 12),
                rawSize: ReadUInt32(data, off + 16),
                rawStart: ReadUInt32(data, off + 20),
                characteristics: ReadUInt32(data, off + 36)));
        }

        // Scan every executable section, not just ".text": gadgets can live in
        // any code section, and not every compiler/packer calls it ".text".
        foreach (var sec in sections.Where(s => (s.Characteristics & ImageScnMemExecute) != 0))
            ScanSection(data, sec, imageBase, gadgets);

        var deduped = gadgets
            .GroupBy(g => (g.GadgetVa, g.CallVa))
            .Select(g => g.First())
            .ToList();

        return new FileResult(path, deduped, "");
    }

    private static void ScanSection(byte[] data, SectionInfo sec, ulong imageBase, List<Gadget> gadgets)
    {
        var start = sec.RawStart;
        var end = start + sec.RawSize;
        if (end > data.Length)
            end = (uint)data.Length;
        if (start >= end)
            return;

        for (var i = start; i < end; i++)
        {
            foreach (var p in Patterns)
            {
                // A REX-prefixed form (r12-r15) actually begins one byte earlier.
                if (p.RequiresRex && i == start)
                    continue;
                var instrStart = p.RequiresRex ? i - 1 : i;

                // Require / forbid the REX.B prefix so r14 (41 FF 26) and rsi
                // (FF 26), r15 (41 FF 27) and rdi (FF 27), etc. never collide.
                if (p.RequiresRex)
                {
                    if (data[i - 1] != 0x41) continue;
                }
                else if (i > start && data[i - 1] == 0x41)
                {
                    continue; // extended-register form; the REX pattern owns it
                }

                // Bounds-check, then match FF + ModRM (+ SIB / disp).
                if (i + (uint)p.OpcodeBytes.Length > end)
                    continue;

                var matched = true;
                for (var k = 0; k < p.OpcodeBytes.Length; k++)
                {
                    if (data[i + (uint)k] != p.OpcodeBytes[k]) { matched = false; break; }
                }
                if (!matched)
                    continue;

                // Require ANY call instruction ending exactly where the gadget
                // begins, i.e. `call x ; jmp qword ptr [reg]`. Constrained to this
                // section, so no underflow and no cross-section match. RVAs come
                // straight from the section we're already in (no per-byte lookup).
                var calls = FindPrecedingCalls(data, instrStart, start, imageBase, sec.VirtAddr, sec.RawStart);
                var gadgetVa = imageBase + RvaOf(sec, instrStart);
                foreach (var (callStart, callText) in calls)
                {
                    var callVa = imageBase + RvaOf(sec, callStart);
                    gadgets.Add(new Gadget(p.Name, gadgetVa, callVa, callText));
                }

                break; // at most one pattern matches a given position
            }
        }
    }

    private static uint RvaOf(SectionInfo sec, uint fileOffset) =>
        sec.VirtAddr + (fileOffset - sec.RawStart);


    // Tries every byte offset backward from jmpStart (within maxBack) and accepts
    // any offset where Iced decodes a valid `call` instruction ending EXACTLY at
    // jmpStart. This is what makes it a hybrid: it still explores unaligned/
    // overlapping starts like your byte-matcher did, but each candidate is now
    // validated by a real decoder instead of hand-rolled ModRM matching.
    private static List<(uint CallStart, string CallText)> FindPrecedingCalls(
        byte[] data, uint jmpStart, uint sectionStart, ulong imageBase, uint sectionRva, uint sectionRawStart,
        int maxBack = 16)
    {
        var found = new List<(uint, string)>();
        var lowest = jmpStart - sectionStart < maxBack ? sectionStart : jmpStart - (uint)maxBack;

        for (long start = jmpStart; start >= lowest; start--)
        {
            var len = (int)(jmpStart - start);
            if (len < 2) continue; // shortest call encoding is 2 bytes (FF /2 reg-indirect)

            var rva = sectionRva + ((uint)start - sectionRawStart);
            var codeReader = new ByteArrayCodeReader(data, (int)start, len);
            var decoder = Iced.Intel.Decoder.Create(64, codeReader, imageBase + rva);

            var instr = decoder.Decode();

            // Must decode cleanly, consume exactly `len` bytes (no trailing slack —
            // that would mean the "call" is actually call+junk), be a real call,
            // and not be a multi-instruction decode (decoder.Decode() only ever
            // returns one instruction, but guard IP advancement anyway).
            if (instr.IsInvalid) continue;
            if (decoder.IP - (imageBase + rva) != (ulong)len) continue;
            if (instr.Mnemonic != Mnemonic.Call) continue;

            found.Add(((uint)start, instr.ToString()));

        }

        return found;
    }


    private static bool CanRead(byte[] data, long offset, long size) =>
        offset >= 0 && size >= 0 && offset + size <= data.Length;

    private static ushort ReadUInt16(byte[] b, uint off) => BitConverter.ToUInt16(b, (int)off);
    private static uint ReadUInt32(byte[] b, uint off) => BitConverter.ToUInt32(b, (int)off);
    private static ulong ReadUInt64(byte[] b, uint off) => BitConverter.ToUInt64(b, (int)off);

    private static string ReadAsciiString(byte[] data, uint offset, int maxLen)
    {
        var len = (int)Math.Min(data.Length - offset, maxLen);
        return Encoding.ASCII.GetString(data, (int)offset, len).TrimEnd('\0');
    }
}

internal sealed class JmpPattern(string name, bool requiresRex, byte[] opcodeBytes)
{
    public string Name { get; } = name;
    public bool RequiresRex { get; } = requiresRex;
    public byte[] OpcodeBytes { get; } = opcodeBytes;
}

internal struct SectionInfo(
    string name, uint virtSize, uint virtAddr, uint rawSize, uint rawStart, uint characteristics)
{
    public string Name { get; } = name;
    public uint VirtSize { get; } = virtSize;
    public uint VirtAddr { get; } = virtAddr;
    public uint RawSize { get; } = rawSize;
    public uint RawStart { get; } = rawStart;
    public uint Characteristics { get; } = characteristics;
}

internal sealed class FileResult(string path, List<Gadget> gadgets, string error)
{
    public string Path { get; } = path;
    public List<Gadget> Gadgets { get; } = gadgets;
    public string Error { get; } = error;   // empty when the file parsed without incident
}

internal sealed class Gadget(string name, ulong gadgetVa, ulong callVa, string callText)
{
    public string Name { get; } = name;
    public ulong GadgetVa { get; } = gadgetVa;
    public ulong CallVa { get; } = callVa;
    public string CallText { get; } = callText;
}
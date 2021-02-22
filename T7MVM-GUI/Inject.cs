using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace T7MVM_GUI
{
    class Inject
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
           int dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
   UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress,
            IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
IntPtr hProcess,
IntPtr lpBaseAddress,
[Out] byte[] lpBuffer,
int dwSize,
out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        private IntPtr handle = IntPtr.Zero,
            buffer = IntPtr.Zero;

        private string exe_name = "",
            dll_path = "";


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_BY_NAME
        {
            public short Hint;
            public byte Name;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORYMODULE
        {
            public IMAGE_NT_HEADERS headers;
            public IntPtr codeBase;
            public IntPtr modules;
            public int numModules;
            public int initialized;

        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint CharacteristicsOrOriginalFirstThunk;    // 0 for terminating null import descriptor; RVA to original unbound IAT (PIMAGE_THUNK_DATA)
            public uint TimeDateStamp;                          // 0 if not bound, -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND); O.W. date/time stamp of DLL bound to (Old BIND)
            public uint ForwarderChain;                         // -1 if no forwarders
            public uint Name;
            public uint FirstThunk;                             // RVA to IAT (if bound this IAT has actual addresses)
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            public fixed sbyte Name[8];

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt64 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string SectionName {
                get {
                    fixed (sbyte* nameBytes = Name)
                        return new string(nameBytes);
                }
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;       // Magic number
            public UInt16 e_cblp;        // Bytes on last page of file
            public UInt16 e_cp;          // Pages in file
            public UInt16 e_crlc;        // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;          // Initial (relative) SS value
            public UInt16 e_sp;          // Initial SP value
            public UInt16 e_csum;        // Checksum
            public UInt16 e_ip;          // Initial IP value
            public UInt16 e_cs;          // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;        // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;        // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;        // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        private bool init = false;

        public bool attach(string _exe_name)
        {
            exe_name = _exe_name;
            var procs = Process.GetProcessesByName(_exe_name);

            if (procs.Length == 0)
                return false;

            handle = OpenProcess(ProcessAccessFlags.All, false, procs[0].Id);

            if (handle == IntPtr.Zero)
                return false;

            init = true;
            return init;
        }

        public int standard(byte[] dll, out string dll_name)
        {
            dll_name = "";
            if (!init)
                return 1;

            dll_path = Path.GetTempPath() + Guid.NewGuid().ToString() + ".dll";
            dll_name = dll_path;
            File.WriteAllBytes(dll_path, dll);

            buffer = VirtualAllocEx(handle, (IntPtr)null, (uint)dll_path.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

            if (buffer == IntPtr.Zero)
                return 2;

            var lla = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (lla == IntPtr.Zero)
                return 3;

            var bytes = Encoding.Default.GetBytes(dll_path);
            if (WriteProcessMemory(handle, buffer, bytes, (uint)bytes.Length, 0) == 0)
                return 4;

            if (CreateRemoteThread(handle, (IntPtr)null, IntPtr.Zero, lla, buffer, 0, (IntPtr)null) == IntPtr.Zero)
                return 5;

            CloseHandle(handle);

            return 0;
        }

        public bool cleanup()
        {
            if (dll_path != string.Empty)
                File.Delete(dll_path);
            return File.Exists(dll_path);
        }

        internal static class Win32Imports
        {
            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern UInt32 GetProcAddress(IntPtr hModule, String procName);

            [DllImport("kernel32")]
            public static extern Int32 LoadLibrary(String lpFileName);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetProcAddress(IntPtr module, IntPtr ordinal);

            [DllImport("kernel32")]
            public static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern Boolean VirtualFree(IntPtr lpAddress, UIntPtr dwSize, UInt32 dwFreeType);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern Boolean VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        }

        internal static class PointerHelpers
        {
            public static T ToStruct<T>(byte[] data) where T : struct
            {
                unsafe
                {
                    fixed (byte* p = &data[0])
                    {
                        return (T)Marshal.PtrToStructure(new IntPtr(p), typeof(T));
                    }
                }
            }

            public static T ToStruct<T>(byte[] data, uint from) where T : struct
            {
                unsafe
                {
                    fixed (byte* p = &data[from])
                    {
                        return (T)Marshal.PtrToStructure(new IntPtr(p), typeof(T));
                    }
                }
            }

            public static T ToStruct<T>(IntPtr ptr, uint from) where T : struct
            {
                return (T)Marshal.PtrToStructure(ptr + (int)from, typeof(T));
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        unsafe delegate bool fnDllEntry(Int64 instance, uint reason, void* reserved);

        internal unsafe bool LoadLibrary(byte[] data)
        {
            //fnDllEntry dllEntry;
            var dosHeader = PointerHelpers.ToStruct<IMAGE_DOS_HEADER>(data);

            var oldHeader = PointerHelpers.ToStruct<IMAGE_NT_HEADERS>(data, (uint)dosHeader.e_lfanew);

            var code = (IntPtr)(VirtualAllocEx(handle, (IntPtr)oldHeader.OptionalHeader.ImageBase, oldHeader.OptionalHeader.SizeOfImage, AllocationType.Reserve, MemoryProtection.ReadWrite));

            if (code.ToInt64() == 0)
                code = (IntPtr)(VirtualAllocEx(handle, (IntPtr)code, oldHeader.OptionalHeader.SizeOfImage, AllocationType.Reserve, MemoryProtection.ReadWrite));

            module = new MEMORYMODULE { codeBase = code, numModules = 0, modules = new IntPtr(0), initialized = 0 };

            VirtualAllocEx(handle, (IntPtr)code, oldHeader.OptionalHeader.SizeOfImage, AllocationType.Commit, MemoryProtection.ReadWrite);

            var headers = (IntPtr)(VirtualAllocEx(handle, (IntPtr)code, oldHeader.OptionalHeader.SizeOfHeaders, AllocationType.Commit, MemoryProtection.ReadWrite));

            WriteProcessMemory(handle, headers, data, (uint)(dosHeader.e_lfanew + oldHeader.OptionalHeader.SizeOfHeaders), 0);

            byte[] buf = new byte[Marshal.SizeOf(module.headers)];
            IntPtr bytes_read;
            ReadProcessMemory(handle, headers + dosHeader.e_lfanew, buf, Marshal.SizeOf(module.headers), out bytes_read);

            module.headers = PointerHelpers.ToStruct<IMAGE_NT_HEADERS>(buf);

            module.headers.OptionalHeader.ImageBase = (ulong)code;

            CopySections(data, oldHeader, headers, dosHeader);

            var locationDelta = (uint)(code.ToInt64() - (long)oldHeader.OptionalHeader.ImageBase);

            if (locationDelta != 0)
                PerformBaseRelocation(locationDelta);

            BuildImportTable();
            FinalizeSections(headers, dosHeader, oldHeader);

            bool success = false;

            try
            {
                fnDllEntry dllEntry =
                    (fnDllEntry)
                    Marshal.GetDelegateForFunctionPointer(
                        new IntPtr(module.codeBase.ToInt64() + (int)module.headers.OptionalHeader.AddressOfEntryPoint),
                        typeof(fnDllEntry));
                success = dllEntry(code.ToInt64(), 1, (void*)0);
            }
            catch (Exception ex)
            {
                return false;
            }
            return success;
        }

        public int GetModuleCount()
        {
            int count = 0;
            IntPtr codeBase = module.codeBase;
            IMAGE_DATA_DIRECTORY directory = module.headers.OptionalHeader.ImportTable;
            if (directory.Size > 0)
            {
                var importDesc = PointerHelpers.ToStruct<IMAGE_IMPORT_DESCRIPTOR>(codeBase, directory.VirtualAddress);
                while (importDesc.Name > 0)
                {
                    var str = codeBase + (int)importDesc.Name;
                    string tmp = Marshal.PtrToStringAnsi(str);
                    int handle = Win32Imports.LoadLibrary(tmp);

                    if (handle == -1)
                    {
                        break;
                    }
                    count++;
                    importDesc = PointerHelpers.ToStruct<IMAGE_IMPORT_DESCRIPTOR>(codeBase, (uint)(directory.VirtualAddress + (Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR)) * (count))));
                }
            }
            return count;
        }

        public int BuildImportTable()
        {
            int ucount = GetModuleCount();
            module.modules = Marshal.AllocHGlobal((ucount) * sizeof(int));
            int pcount = 0;
            int result = 1;
            IntPtr codeBase = module.codeBase;
            IMAGE_DATA_DIRECTORY directory = module.headers.OptionalHeader.ImportTable;
            if (directory.Size > 0)
            {
                var importDesc = PointerHelpers.ToStruct<IMAGE_IMPORT_DESCRIPTOR>(codeBase, directory.VirtualAddress);
                while (importDesc.Name > 0)
                {
                    var str = codeBase + (int)importDesc.Name;
                    string tmp = Marshal.PtrToStringAnsi(str);
                    unsafe
                    {
                        uint* thunkRef;
                        uint* funcRef;

                        int handle = Win32Imports.LoadLibrary(tmp);

                        if (handle == -1)
                        {
                            result = 0;
                            break;
                        }

                        if (importDesc.CharacteristicsOrOriginalFirstThunk > 0)
                        {
                            IntPtr thunkRefAddr = codeBase + (int)importDesc.CharacteristicsOrOriginalFirstThunk;
                            thunkRef = (uint*)thunkRefAddr;
                            funcRef = (uint*)(codeBase + (int)importDesc.FirstThunk);
                        }
                        else
                        {
                            thunkRef = (uint*)(codeBase + (int)importDesc.FirstThunk);
                            funcRef = (uint*)(codeBase + (int)importDesc.FirstThunk);
                        }
                        for (; *thunkRef > 0; thunkRef++, funcRef++)
                        {
                            if ((*thunkRef & 0x80000000) != 0)
                            {
                                *funcRef = (uint)Win32Imports.GetProcAddress(new IntPtr(handle), new IntPtr(*thunkRef & 0xffff));
                            }
                            else
                            {
                                var str2 = codeBase + (int)(*thunkRef) + 2;
                                var tmpaa = Marshal.PtrToStringAnsi(str2);
                                *funcRef = Win32Imports.GetProcAddress(new IntPtr(handle), tmpaa);
                            }
                            if (*funcRef == 0)
                            {
                                result = 0;
                                break;
                            }
                        }


                        pcount++;
                        importDesc = PointerHelpers.ToStruct<IMAGE_IMPORT_DESCRIPTOR>(codeBase, directory.VirtualAddress + (uint)(Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR)) * pcount));
                    }
                }
            }
            return result;
        }

        static readonly int[][][] ProtectionFlags = new int[2][][];

        public void FinalizeSections(IntPtr headers, IMAGE_DOS_HEADER dosHeader, IMAGE_NT_HEADERS oldHeaders)
        {
            ProtectionFlags[0] = new int[2][];
            ProtectionFlags[1] = new int[2][];
            ProtectionFlags[0][0] = new int[2];
            ProtectionFlags[0][1] = new int[2];
            ProtectionFlags[1][0] = new int[2];
            ProtectionFlags[1][1] = new int[2];
            ProtectionFlags[0][0][0] = 0x01;
            ProtectionFlags[0][0][1] = 0x08;
            ProtectionFlags[0][1][0] = 0x02;
            ProtectionFlags[0][1][1] = 0x04;
            ProtectionFlags[1][0][0] = 0x10;
            ProtectionFlags[1][0][1] = 0x80;
            ProtectionFlags[1][1][0] = 0x20;
            ProtectionFlags[1][1][1] = 0x40;

            var section = PointerHelpers.ToStruct<IMAGE_SECTION_HEADER>(headers, (uint)(24 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader));
            for (int i = 0; i < module.headers.FileHeader.NumberOfSections; i++)
            {
                //Console.WriteLine("Finalizing " + Encoding.UTF8.GetString(section.Name));
                int executable = (section.Characteristics & DataSectionFlags.MemoryDiscardable) != 0 ? 1 : 0;
                int readable = (section.Characteristics & DataSectionFlags.MemoryNotCached) != 0 ? 1 : 0;
                int writeable = (section.Characteristics & DataSectionFlags.MemoryNotPaged) != 0 ? 1 : 0;

                if ((section.Characteristics & DataSectionFlags.MemoryDiscardable) > 0)
                {
                    bool aa = VirtualFreeEx(handle, new IntPtr((long)section.VirtualAddress), (int)section.SizeOfRawData, AllocationType.Decommit);
                    continue;
                }

                var protect = (uint)ProtectionFlags[executable][readable][writeable];

                if ((section.Characteristics & DataSectionFlags.MemoryNotCached) > 0)
                    protect |= 0x200;
                var size = (int)section.SizeOfRawData;
                if (size == 0)
                {
                    if ((section.Characteristics & DataSectionFlags.ContentInitializedData) > 0)
                        size = (int)module.headers.OptionalHeader.SizeOfInitializedData;
                    else if ((section.Characteristics & DataSectionFlags.ContentUninitializedData) > 0)
                        size = (int)module.headers.OptionalHeader.SizeOfUninitializedData;

                }

                if (size > 0)
                {
                    uint oldProtect;
                    if (!VirtualProtectEx(handle, new IntPtr((long)section.VirtualAddress), (UIntPtr)section.SizeOfRawData, protect, out oldProtect))
                    {
                    }
                }

                section = PointerHelpers.ToStruct<IMAGE_SECTION_HEADER>(headers, (uint)((24 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * (i + 1))));
            }
        }

        public void PerformBaseRelocation(uint delta)
        {
            IntPtr codeBase = module.codeBase;
            int sizeOfBase = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            IMAGE_DATA_DIRECTORY directory = module.headers.OptionalHeader.BaseRelocationTable;
            int cnt = 0;
            if (directory.Size > 0)
            {
                var relocation = PointerHelpers.ToStruct<IMAGE_BASE_RELOCATION>(codeBase, directory.VirtualAddress);
                while (relocation.VirtualAddress > 0)
                {
                    unsafe
                    {
                        var dest = (IntPtr)(codeBase.ToInt64() + (int)relocation.VirtualAddress);
                        var relInfo = (ushort*)(codeBase.ToInt64() + (int)directory.VirtualAddress + sizeOfBase);
                        uint i;
                        for (i = 0; i < ((relocation.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2); i++, relInfo++)
                        {
                            int type = *relInfo >> 12;
                            int offset = (*relInfo & 0xfff);
                            switch (type)
                            {
                                case 0x00:
                                    break;
                                case 0x03:
                                    var patchAddrHl = (uint*)((dest) + (offset));
                                    *patchAddrHl += delta;
                                    break;
                            }
                        }
                    }
                    cnt += (int)relocation.SizeOfBlock;
                    relocation = PointerHelpers.ToStruct<IMAGE_BASE_RELOCATION>(codeBase, (uint)(directory.VirtualAddress + cnt));

                }
            }
        }

        private MEMORYMODULE module;
        public uint GetProcAddress(string name)
        {
            unsafe
            {
                IntPtr codeBase = module.codeBase;
                int idx = -1;
                uint i;
                IMAGE_DATA_DIRECTORY directory = module.headers.OptionalHeader.ExportTable;
                if (directory.Size == 0)
                    return 0;
                var exports = PointerHelpers.ToStruct<IMAGE_EXPORT_DIRECTORY>(codeBase, directory.VirtualAddress);
                var nameRef = (uint*)new IntPtr(codeBase.ToInt64() + exports.AddressOfNames);
                var ordinal = (ushort*)new IntPtr(codeBase.ToInt64() + exports.AddressOfNameOrdinals);
                for (i = 0; i < exports.NumberOfNames; i++, nameRef++, ordinal++)
                {
                    var str = codeBase + (int)(*nameRef);
                    string tmp = Marshal.PtrToStringAnsi(str);
                    if (tmp == name)
                    {
                        idx = *ordinal;
                        break;
                    }
                }

                var tmpaa = (uint*)(codeBase.ToInt64() + (exports.AddressOfFunctions + (idx * 4)));
                var addr = (uint)((codeBase.ToInt64()) + (*tmpaa));
                return addr;
            }
        }

        public void CopySections(byte[] data, IMAGE_NT_HEADERS oldHeaders, IntPtr headers, IMAGE_DOS_HEADER dosHeader)
        {
            int i;
            IntPtr codebase = module.codeBase;

            byte[] buf = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
            IntPtr bytes_read;


            ReadProcessMemory(handle, (IntPtr)((Int64)headers + (uint)(24 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader)), buf, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)), out bytes_read);

            var section = PointerHelpers.ToStruct<IMAGE_SECTION_HEADER>(buf);
            for (i = 0; i < module.headers.FileHeader.NumberOfSections; i++)
            {
                IntPtr dest;
                if (section.SizeOfRawData == 0)
                {
                    uint size = oldHeaders.OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        dest = new IntPtr((int)VirtualAllocEx(handle, (IntPtr)(codebase.ToInt64() + (int)section.VirtualAddress), size, AllocationType.Commit, MemoryProtection.ReadWrite));

                        section.VirtualAddress = (uint)dest;
                        var write = new IntPtr(headers.ToInt64() + (32 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * (i)));

                        WriteProcessMemory(handle, write, BitConverter.GetBytes((int)dest), (uint)Marshal.SizeOf(dest), 0);
                    }

                    ReadProcessMemory(handle, (IntPtr)((Int64)headers + (uint)((24 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * (i + 1)))), buf, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)), out bytes_read);

                    section = PointerHelpers.ToStruct<IMAGE_SECTION_HEADER>(buf);
                    continue;
                }

                dest = VirtualAllocEx(handle, (IntPtr)(codebase.ToInt64() + (int)section.VirtualAddress), section.SizeOfRawData, AllocationType.Commit, MemoryProtection.ReadWrite);

                byte[] raw_data = new byte[section.SizeOfRawData];
                Array.Copy(data, (int)section.PointerToRawData, raw_data, 0, (int)section.SizeOfRawData);
                WriteProcessMemory(handle, dest, raw_data, section.SizeOfRawData, 0);

                section.VirtualAddress = (ulong)dest;
                var write2 = new IntPtr(headers.ToInt64() + (32 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * (i)));
                WriteProcessMemory(handle, write2, BitConverter.GetBytes((ulong)dest), (uint)Marshal.SizeOf(dest), 0);

                ReadProcessMemory(handle, (IntPtr)((Int64)headers + (uint)((24 + dosHeader.e_lfanew + oldHeaders.FileHeader.SizeOfOptionalHeader) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * (i + 1)))), buf, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)), out bytes_read);

                section = PointerHelpers.ToStruct<IMAGE_SECTION_HEADER>(buf);
            }
        }
    }
}

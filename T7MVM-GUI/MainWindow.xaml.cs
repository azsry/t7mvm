using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace T7MVM_GUI
{
    public partial class MainWindow
    {
        uint BUF_SIZE = 65535;
        IntPtr buffer = IntPtr.Zero,
            map_file = IntPtr.Zero,
            req_ptr = IntPtr.Zero;

        [Flags]
        public enum request_type : int
        {
            type_timescale = 0,
            type_dllname,
            type_console,
            type_max
        }

        [StructLayout(LayoutKind.Sequential)]
        class request
        {
            public request()
            {
                magic = 0;
                type = request_type.type_max;
                data = new char[255];
            }

            public Int32 magic;
            public request_type type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255)]
            public char[] data;
        }

        [Flags]
        public enum FileMapProtection : uint
        {
            PageReadonly = 0x02,
            PageReadWrite = 0x04,
            PageWriteCopy = 0x08,
            PageExecuteRead = 0x20,
            PageExecuteReadWrite = 0x40,
            SectionCommit = 0x8000000,
            SectionImage = 0x1000000,
            SectionNoCache = 0x10000000,
            SectionReserve = 0x4000000,
        }

        [Flags]
        public enum FileMapAccess : uint
        {
            FileMapCopy = 0x0001,
            FileMapWrite = 0x0002,
            FileMapRead = 0x0004,
            FileMapAllAccess = 0x001f,
            FileMapExecute = 0x0020,
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateFileMapping(
    IntPtr hFile,
    IntPtr lpFileMappingAttributes,
    FileMapProtection flProtect,
    uint dwMaximumSizeHigh,
    uint dwMaximumSizeLow,
    [MarshalAs(UnmanagedType.LPStr)] string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr MapViewOfFile(
    IntPtr hFileMappingObject,
    FileMapAccess dwDesiredAccess,
    uint dwFileOffsetHigh,
    uint dwFileOffsetLow,
    UIntPtr dwNumberOfBytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

        Inject inj = new Inject();

        public MainWindow()
        {
            InitializeComponent();
        }

        public int get_time()
        {
            var t = (DateTime.UtcNow - new DateTime(1970, 1, 1));
            return (int)t.TotalSeconds;
        }

        private void Set_timescale_Click(object sender, RoutedEventArgs e)
        {
            var req = new request();
            req.magic = get_time();
            double data_float = 0f;

            req.type = request_type.type_timescale;

            if (!double.TryParse(timescale.Text, out data_float))
            {
                statusbar_label.Text = $"Failed to parse input: {timescale.Text}";
                return;
            }

            var bytes = BitConverter.GetBytes(data_float);

            Array.Copy(bytes, req.data, bytes.Length);
            var size = Marshal.SizeOf(req);

            statusbar_label.Text = $"Magic = {req.magic} | Data = {BitConverter.ToString(bytes).Replace("-", string.Empty)}";

            req_ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(req, req_ptr, true);

            CopyMemory(buffer, req_ptr, (uint)Marshal.SizeOf(req));
        }

        private void Send_cmd_Click(object sender, RoutedEventArgs e)
        {
            var req = new request();
            req.magic = get_time();

            req.type = request_type.type_console;

            var bytes = ASCIIEncoding.ASCII.GetBytes(console_cmd.Text);

            Array.Copy(bytes, req.data, bytes.Length);
            var size = Marshal.SizeOf(req);

            statusbar_label.Text = $"Magic = {req.magic} | Data = {BitConverter.ToString(bytes).Replace("-", string.Empty)}";

            req_ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(req, req_ptr, true);

            CopyMemory(buffer, req_ptr, (uint)Marshal.SizeOf(req));
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (!inj.attach("BlackOps3"))
            {
                statusbar_label.Text = $"Could not find Black Ops 3! Error {Marshal.GetLastWin32Error()}";
                return;
            }

            string dll_name;
            var ret = inj.standard(dll._dll, out dll_name);

            if (ret != 0)
            {
                switch (ret)
                {
                    case 1:
                        statusbar_label.Text = $"Failed to attach to Black Ops 3 ({Marshal.GetLastWin32Error()})";
                        break;
                    case 2:
                        statusbar_label.Text = $"VirtualAllocEx failed! ({Marshal.GetLastWin32Error()})";
                        break;
                    case 3:
                        statusbar_label.Text = $"Failed to get LLA address ({Marshal.GetLastWin32Error()})";
                        break;
                    case 4:
                        statusbar_label.Text = $"WriteProcessMemory failed! ({Marshal.GetLastWin32Error()}";
                        break;
                    case 5:
                        statusbar_label.Text = $"CreateRemoteThread failed! ({Marshal.GetLastWin32Error()})";
                        break;
                }
            }

            //var ret = inj.LoadLibrary(dll._dll);

            //if (!ret)
            //{
            //    statusbar_label.Text = "Failed to load T7MVM!";
            //    return;
            //}

            statusbar_label.Text = "T7MVM loaded!";

            map_file = CreateFileMapping(new IntPtr(-1), IntPtr.Zero, FileMapProtection.PageReadWrite, 0, BUF_SIZE, "Local\\T7MVM");

            if (map_file == IntPtr.Zero)
            {
                statusbar_label.Text = $"CreateFileMapping failed! Error {Marshal.GetLastWin32Error()}";
                CloseHandle(map_file);
                return;
            }

            Thread.Sleep(500);

            var req = new request();
            req.magic = get_time();
            req.type = request_type.type_dllname;
            var bytes = dll_name.ToCharArray();

            Array.Copy(bytes, req.data, bytes.Length);

            req_ptr = Marshal.AllocHGlobal(Marshal.SizeOf(req));
            Marshal.StructureToPtr(req, req_ptr, true);

            buffer = MapViewOfFile(map_file, FileMapAccess.FileMapAllAccess, 0, 0, (UIntPtr)BUF_SIZE);

            if (buffer == IntPtr.Zero)
            {
                statusbar_label.Text = $"MapViewOfFile failed! Error {Marshal.GetLastWin32Error()}";
                CloseHandle(map_file);
                return;
            }

            CopyMemory(buffer, req_ptr, (uint)Marshal.SizeOf(req));

            statusbar_label.Text = "Ready to send";
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (buffer != IntPtr.Zero)
                UnmapViewOfFile(buffer);

            if (map_file != IntPtr.Zero)
                CloseHandle(map_file);

            Marshal.FreeHGlobal(req_ptr);

            //inj.cleanup();
        }
    }
}

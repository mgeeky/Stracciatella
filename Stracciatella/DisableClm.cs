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

namespace Stracciatella
{
    class DisableClm
    {
        private static int ENCODED_RESOURCE_XOR_KEY = 0xAF;

        public static string ExtractResource(string resourceName)
        {
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();
                using (Stream rsrcStream = asm.GetManifestResourceStream(asm.GetName().Name + ".Properties." + resourceName))
                {
                    using (StreamReader sRdr = new StreamReader(rsrcStream))
                    {
                        //For instance, gets it as text
                        return sRdr.ReadToEnd();
                    }
                }
            } catch { }

            return "";
        }

        // source: https://stackoverflow.com/a/12974852
        private static bool CheckDirectoryWritePrivilege(string path, FileSystemRights AccessRight)
        {
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                DirectorySecurity acl = di.GetAccessControl();
                AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(currentUser);
                foreach (AuthorizationRule rule in rules)
                {
                    FileSystemAccessRule fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & FileSystemRights.WriteData) > 0)
                    {
                        NTAccount ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                        {
                            continue;
                        }

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
            }

            return false;
        }

        // Source: https://stackoverflow.com/a/5957525
        public static class SafeWalk
        {
            public static IEnumerable<string> EnumerateFiles(string path, string searchPattern, SearchOption searchOpt)
            {
                try
                {
                    var dirFiles = Enumerable.Empty<string>();
                    if (searchOpt == SearchOption.AllDirectories)
                    {
                        dirFiles = Directory.EnumerateDirectories(path)
                                            .SelectMany(x => EnumerateFiles(x, searchPattern, searchOpt));
                    }
                    return dirFiles.Concat(Directory.EnumerateFiles(path, searchPattern));
                }
                catch (UnauthorizedAccessException ex)
                {
                    return Enumerable.Empty<string>();
                }
            }
        }

        private static string FindWritableImplantPath(string root)
        {
            foreach (string f in SafeWalk.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
            {
                string p = Path.GetDirectoryName(f);
                if (CheckDirectoryWritePrivilege(p, FileSystemRights.FullControl))
                {
                    return p;
                }
            }

            return "";
        }

        public static bool WriteResourceToFile(string resourceName, string destFile)
        {
            string buf = ExtractResource(resourceName);
            if (buf.Length == 0)
                return false;

            return true;
        }

        public static bool DoDisable(PowerShell rs)
        {
            bool ret = false;

            // FIXME: Not implemented yet.
            return true;

            string path = FindWritableImplantPath(Environment.GetEnvironmentVariable("USERPROFILE"));
            if (path.Length == 0)
                return false;

            //WriteResourceToFile()

            return ret;
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace InvokeRecon
{
    internal class Files
    {
        public static void Invoke()
        {
            var patterns = new string[]{
                // Wildcards
                "*pass*",
                "*diagram*",
                "*_rsa*",

                // Extensions
                "*.doc",
                "*.docx",
                "*.pem",
                "*.pdf",
                "*.pfx",
                "*.p12",
                "*.ppt",
                "*.ppk",
                "*.pptx",
                "*.vsd",
                "*.xls",
                "*.xlsx",
                "*.kdb",
                "*.kdbx",
                "*.key",
                "*.rdp",
                "*.sdtid",
                "*.ovpn",
                "*.psafe3",
                "*.cscfg",
                "*.tblk",
                "*.bkf",
                "*.v2i",
                "*.gho",
                "*.vbk",
                "*.tib",
                "*.tibx",
                "*.mtf",

                // Specific file names
                "KeePass.config",
                "ConsoleHost_history.txt",
            };

            var searchPath = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";
            var files = FindFiles(searchPath, string.Join(";", patterns));

            foreach (var file in files)
            {
                var info = new FileInfo(file);

                //string owner = null;
                //string sddl = null;
                //try
                //{
                //    sddl = info.GetAccessControl(System.Security.AccessControl.AccessControlSections.All).GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.All);
                //    owner = File.GetAccessControl(file).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                //}
                //catch { }

                Console.WriteLine("{2,0} {1,-13} {0}", file, info.Length, info.LastAccessTime);
            }
        }

        public static List<string> FindFiles(string path, string patterns)
        {
            var files = new List<string>();
            try
            {
                var filesUnfiltered = GetFiles(path).ToList();

                foreach (var pattern in patterns.Split(';'))
                {
                    files.AddRange(filesUnfiltered.Where(f => f.Contains(pattern.Trim('*'))));
                }

                //// go recurse in all sub-directories
                //foreach (var directory in Directory.GetDirectories(path))
                //    files.AddRange(FindFiles(directory, patterns));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }

            return files;
        }

        private static IEnumerable<string> GetFiles(string path)
        {
            var queue = new Queue<string>();
            queue.Enqueue(path);
            while (queue.Count > 0)
            {
                path = queue.Dequeue();
                try
                {
                    foreach (var subDir in Directory.GetDirectories(path))
                    {
                        queue.Enqueue(subDir);
                    }
                }
                catch (Exception)
                { }
                string[] files = null;
                try
                {
                    files = Directory.GetFiles(path);
                }
                catch (Exception)
                { }

                if (files == null) continue;
                foreach (var f in files)
                {
                    yield return f;
                }
            }
        }
    }
}
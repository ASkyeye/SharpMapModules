using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace InvokeRecon
{
    internal class Misc
    {
        public static void Invoke()
        {
            string[] drives = Environment.GetLogicalDrives();
            Console.WriteLine();
            Console.WriteLine("[*] Listing Drives");
            foreach (string drive in drives)
            {
                Console.WriteLine("[*] Drive: {0}", drive);
            }

            Console.WriteLine();
            Console.WriteLine("[*] Dpapi");
            dpapi();
        }

        static void dpapi()
        {
            var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            var userFolder = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

            var credentialFolders = new List<string>()
            {
                $"{systemRoot}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
                $"{systemRoot}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
                $"{systemRoot}\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials",
                $"{systemRoot}\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials",
                $"{systemRoot}\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials",
                $"{systemRoot}\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials"
            };

            foreach (var dir in Directory.GetDirectories(userFolder))
            {
                if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") ||
                    dir.EndsWith("All Users"))
                {
                    continue;
                }

                credentialFolders.Add($"{dir}\\AppData\\Local\\Microsoft\\Credentials\\");
                credentialFolders.Add($"{dir}\\AppData\\Roaming\\Microsoft\\Credentials\\");
            };

            foreach (var credPath in credentialFolders)
            {
                if (!Directory.Exists(credPath))
                    continue;
                var userFiles = Directory.GetFiles(credPath);
                if (userFiles.Length == 0)
                    continue;
                foreach (string file in userFiles)
                {
                    var size = new FileInfo(file).Length;
                    var credentialArray = File.ReadAllBytes(file);
                    var guidMasterKeyArray = new byte[16];
                    Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16);
                    var guidMasterKey = new Guid(guidMasterKeyArray);

                    var stringLenArray = new byte[16];
                    Array.Copy(credentialArray, 56, stringLenArray, 0, 4);
                    var descLen = BitConverter.ToInt32(stringLenArray, 0);

                    var descBytes = new byte[descLen - 4];
                    Array.Copy(credentialArray, 60, descBytes, 0, descBytes.Length);

                    var desc = Encoding.Unicode.GetString(descBytes);

                    Console.WriteLine("FileName     : {0}", Path.GetFileName(file));
                    Console.WriteLine("Description  : {0}", desc);
                    Console.WriteLine("MasterKey    : {0}", guidMasterKey);
                    Console.WriteLine("Accessed     : {0}", File.GetLastAccessTime(file));
                    Console.WriteLine("Modified     : {0}", File.GetLastAccessTime(file));
                    Console.WriteLine("Size         : {0}\n", size);
                }
            }
        }
    }
}
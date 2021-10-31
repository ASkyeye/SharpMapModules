using System;
using System.IO;
using System.Linq;

namespace InvokeRecon
{
    internal class Folders
    {
        public static void Invoke()
        {
            var dirs = Directory.GetDirectories("\\Users\\");
            string[] list = {
                ".bluemix",
                ".azure",
                ".aws",
                "AppData\\Roaming\\gcloud",
                "Documents\\SuperPuTTY",
                "AppData\\Roaming\\FileZilla",
                "AppData\\Roaming\\KeePass",
                "AppData\\Roaming\\Windows Azure Powershell",
                "AppData\\Roaming\\Mozilla\\Firefox",
                "AppData\\Local\\Google\\Chrome",
                "AppData\\Roaming\\Slack\\Cookies",
                "AppData\\Local\\Microsoft\\Remote Desktop Connection Manager",
                "AppData\\Roaming\\Microsoft\\StickyNotes"
            };

            foreach (string dir in dirs)
            {
                if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                    continue;

                foreach (string software in list)
                {
                    try
                    {
                        if (Directory.Exists(dir + "\\" + software))
                        {
                            string path = dir + "\\" + software;
                            var info = new DirectoryInfo(path);
                            Console.WriteLine("{2,0} {1,-13} {0}", path, info.EnumerateFiles("*.*", SearchOption.AllDirectories).Sum(fi => fi.Length), info.LastAccessTime);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.ToString());
                    }
                }
            }
        }
    }
}
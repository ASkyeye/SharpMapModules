using Microsoft.Win32;
using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace InvokeRecon
{
    internal class Registry
    {
        public static void Invoke()
        {
            var regex = new Regex($@"S-1-5-21-[\d\-]+$");
            RegistryKey usersKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, Environment.MachineName);
            string[] list = {
                "SOFTWARE\\Wow6432Node\\RealVNC",
                "SOFTWARE\\RealVNC",
                "SOFTWARE\\TightVNC",
                "SOFTWARE\\TigerVNC",
                "SOFTWARE\\ORL\\WinVNC3",
                "SOFTWARE\\SimonTatham\\PuTTY\\Session",
                "SOFTWARE\\SimonTatham\\PuTTY\\SshHostKeys",
                "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AltDefaultPassword"
            };
            foreach (string sid in usersKey.GetSubKeyNames().Where(sid => regex.IsMatch(sid)))
            {
                //Console.WriteLine(sid);
                try
                {
                    foreach (string software in list)
                    {
                        try
                        {
                            RegistryKey key = usersKey.OpenSubKey(sid + "\\" + software);
                            key.GetSubKeyNames();
                            Console.WriteLine("[*] {0}", sid + "\\" + software);
                        }
                        catch (NullReferenceException)
                        {
                        }
                    }

                    RegistryKey rdpHive = usersKey.OpenSubKey(sid + @"\SOFTWARE\Microsoft\Terminal Server Client\Servers");
                    try
                    {
                        foreach (string server in rdpHive.GetSubKeyNames())
                        {
                            string username = "";
                            try
                            {
                                username = (string)rdpHive.OpenSubKey(server).GetValue("UsernameHint");
                            }
                            catch { }
                            Console.WriteLine("[*] Saved rdp connection: " + username + "@" + server);
                        }
                    }
                    catch (NullReferenceException)
                    {
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }
            }
            usersKey.Close();
        }
    }
}
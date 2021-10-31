using System;
using System.Collections.Generic;
using System.Diagnostics;
using static GetLsassSessions.Template;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace GetLsassSessions
{
    internal class Program
    {
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        //
        //[Flags]
        //public enum ProcessAccessFlags : uint
        //{
        //    All = 0x001F0FFF,
        //    Terminate = 0x00000001,
        //    CreateThread = 0x00000002,
        //    VirtualMemoryOperation = 0x00000008,
        //    VirtualMemoryRead = 0x00000010,
        //    VirtualMemoryWrite = 0x00000020,
        //    DuplicateHandle = 0x00000040,
        //    CreateProcess = 0x000000080,
        //    SetQuota = 0x00000100,
        //    SetInformation = 0x00000200,
        //    QueryInformation = 0x00000400,
        //    QueryLimitedInformation = 0x00001000,
        //    Synchronize = 0x00100000
        //}

        private static void Main(string[] args)
        {
            IntPtr lsasrv = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;

            Process lsass = Process.GetProcessesByName("lsass")[0];
            ProcessModuleCollection processModules = lsass.Modules;
            foreach (ProcessModule module in processModules)
            {
                string lower = module.ModuleName.ToLowerInvariant();

                if (lower.Contains("lsasrv.dll"))
                {
                    lsasrv = module.BaseAddress;
                    break;
                }
            }
            //hProcess = OpenProcess(ProcessAccessFlags.All, false, plsass.Id);
            List<Logon> logonlist = new List<Logon>();
            LsassTemplate template = getTemplate();
            LogonSessions.FindSessions(lsass.Handle, lsasrv, template, logonlist);
            foreach (Logon log in logonlist)
            {
                Console.WriteLine("=====================================================================");
                Console.WriteLine($"[*] LogonId:     {log.LogonId.HighPart}:{log.LogonId.LowPart}");
                if (!string.IsNullOrEmpty(log.LogonType))
                    Console.WriteLine($"[*] LogonType:   {log.LogonType}");
                Console.WriteLine($"[*] Session:     {log.Session}");
                if (log.LogonTime.dwHighDateTime != 0)
                    Console.WriteLine($"[*] LogonTime:   {ToDateTime(log.LogonTime):yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"[*] UserName:    {log.UserName}");
                if (!string.IsNullOrEmpty(log.SID))
                    Console.WriteLine($"[*] SID:         {log.SID}");
                if (!string.IsNullOrEmpty(log.LogonDomain))
                    Console.WriteLine($"[*] LogonDomain: {log.LogonDomain}");
                if (!string.IsNullOrEmpty(log.LogonServer))
                    Console.WriteLine($"[*] LogonServer: {log.LogonServer}");
                Console.WriteLine();
            }
        }

        public static DateTime ToDateTime(FILETIME time)
        {
            var fileTime = ((long)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;

            try
            {
                return DateTime.FromFileTime(fileTime);
            }
            catch
            {
                return DateTime.FromFileTime(0xFFFFFFFF);
            }
        }
    }
}
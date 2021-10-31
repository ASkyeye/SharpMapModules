using System;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace GetLsassSessions
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public uint HighPart;
    }

    internal class Logon
    {
        public LUID LogonId { get; set; }
        public string LogonType { get; set; }
        public int Session { get; set; }
        public FILETIME LogonTime { get; set; }
        public string UserName { get; set; }
        public string LogonDomain { get; set; }
        public string LogonServer { get; set; }
        public string SID { get; set; }

        public IntPtr pCredentials { get; set; }
        public IntPtr pCredentialManager { get; set; }

        public Logon(LUID logonId)
        {
            LogonId = logonId;
        }
    }
}
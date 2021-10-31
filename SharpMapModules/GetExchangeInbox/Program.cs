using Microsoft.Exchange.WebServices.Data;
using System;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace GetExchangeInbox
{
    internal class TrustAll : System.Net.ICertificatePolicy
    {
        public TrustAll()
        {
        }

        public bool CheckValidationResult(System.Net.ServicePoint sp,
          X509Certificate cert,
          System.Net.WebRequest req, int problem)
        {
            return true;
        }
    }

    internal class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length >= 1)
            {
                connect(args[0]);
            }
            else
            {
                connect();
            }
        }

        public static void connect(string exchange = null)
        {
            string email;
            try
            {
                email = UserPrincipal.Current.EmailAddress;
                if (string.IsNullOrEmpty(email))
                {
                    throw new Exception();
                }
                Console.WriteLine("[*] Email: {0}", email);
            }
            catch
            {
                Console.WriteLine("[-] Failed to get user email");
                return;
            }
            if (string.IsNullOrEmpty(email))
            {
                Console.WriteLine("[-] Failed to get user email");
                return;
            }

            System.Net.ServicePointManager.CertificatePolicy = new TrustAll();
            ExchangeVersion version = ExchangeVersion.Exchange2013;
            ExchangeService service = new ExchangeService(version);
            service.UseDefaultCredentials = true;

            if (!string.IsNullOrEmpty(exchange))
            {
                service.Url = new Uri("https://" + exchange + "/EWS/Exchange.asmx");
            }
            else
            {
                try
                {
                    service.AutodiscoverUrl(email);
                    Console.WriteLine("[*] Exchange: {0}", service.Url);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] AutodiscoverUrl failed {0}", e.ToString());
                    return;
                }
            }

            try
            {
                var msgfolderroot = WellKnownFolderName.MsgFolderRoot;
                var mbx = new Mailbox(email);
                var folderId = new FolderId(msgfolderroot, mbx);
                var rootFolder = Folder.Bind(service, folderId);
                var folderView = new FolderView(100);
                folderView.Traversal = FolderTraversal.Deep;
                rootFolder.Load();
                var CustomFolderObj = rootFolder.FindFolders(folderView);
                foreach (var foldername in CustomFolderObj.Where(folder => !Regex.IsMatch(folder.DisplayName, @"Conversation Action Settings|Outbox|Outbound|Inbound|Feeds|Yammer|Tasks|Cache|GAL|Calendar|Contacts|[({]?[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12}[})]?", RegexOptions.IgnoreCase)))
                {
                    Console.WriteLine("[+] Folder: {0}", foldername.DisplayName);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return;
            }
        }
    }
}
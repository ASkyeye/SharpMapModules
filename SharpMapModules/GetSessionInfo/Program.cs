using System;

namespace InvokeRecon
{
    //to add:
    //cookies
    //vpn
    //kee vaults

    internal class Program
    {
        private static void Main(string[] args)
        {
            Misc.Invoke();
            Console.WriteLine();
            Console.WriteLine("[*] Looking Sensitive Information");
            Console.WriteLine("\nAccessed              Length        Path");
            Console.WriteLine("----------            ----------    -----");
            Folders.Invoke();
            Files.Invoke();
            Registry.Invoke();
        }
    }
}
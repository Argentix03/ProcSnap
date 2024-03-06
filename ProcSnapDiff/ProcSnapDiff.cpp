#include <iostream>
#include <Windows.h>
#include <processsnapshot.h>
#include "KUSER_SHARED_DATA.h"  // currently only has 1 version of the struct and no windows version check

void DisplayThreadInformation(HPSS hSnapshot);
void DisplayProcessInfo(HPSS hSnapshot);
void DisplayHandleInformation(HPSS hSnapshot);
void DisplayVASpace(HPSS hSnapshot);
void DisplayAuxPages(HPSS hSnapshot);
void DisplayKUserSharedData(HANDLE pHandle);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    // Parse PID
    int pid = atoi(argv[1]); // Convert argument to integer
    if (pid <= 0) {
        std::cerr << "Invalid PID. Please enter a positive numeric PID." << std::endl;
        return 1;
    }

    std::cout << "Snapshotting PID: " << pid << std::endl;

    // Get a handle to the process
    HANDLE processHandle = OpenProcess(MAXIMUM_ALLOWED, false, pid);
    if (processHandle == NULL) {
        std::cerr << "Failed to open process with PID " << pid << ". Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Capture the snapshot of the process
    HPSS hSnapshot = NULL;
    PSS_CAPTURE_FLAGS captureFlags = 
        PSS_CAPTURE_VA_CLONE |
        PSS_CAPTURE_HANDLES |
        PSS_CAPTURE_HANDLE_NAME_INFORMATION |
        PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
        PSS_CAPTURE_HANDLE_TRACE | // Not used cuz dunno how
        PSS_CAPTURE_THREADS | 
        PSS_CAPTURE_THREAD_CONTEXT | 
        PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | 
        PSS_CAPTURE_VA_SPACE |
        PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION |
        PSS_CAPTURE_IPT_TRACE;  // I have Ryzen T_T

    if (PssCaptureSnapshot(processHandle, captureFlags, CONTEXT_ALL, &hSnapshot) != ERROR_SUCCESS) {
        std::cerr << "Failed to capture process snapshot. Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Comment out here for faster snapshots
    // or cli argument this
    std::cout << std::endl << "==Process Info==" << std::endl;
    DisplayProcessInfo(hSnapshot);

    std::cout << std::endl << "==Threads Info==" << std::endl;
    DisplayThreadInformation(hSnapshot);

    std::cout << std::endl << "==Handles Info==" << std::endl;
    DisplayHandleInformation(hSnapshot);

    std::cout << std::endl << "==Virtual Memory Info==" << std::endl;
    DisplayVASpace(hSnapshot); // VA bumps it from less than 1s to over 2s on my machine.

    std::cout << std::endl << "==Auxiliary Pages==" << std::endl; // Never got it to work wtf even is this auxiliary pages?
    DisplayAuxPages(hSnapshot); 

    std::cout << std::endl << "==KUSER_SHARED_DATA Info==" << std::endl;
    DisplayKUserSharedData(processHandle);

    // "At this point in the code there shouldnt be a need to manually free" 
    // ...said every wise dev who never leaks anything.
    PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
    CloseHandle(processHandle);
    
    return 0;
}

void DisplayAuxPages(HPSS hSnapshot) {
    
    HPSSWALK walkMarkerHandle = NULL;
    if (PssWalkMarkerCreate(NULL, &walkMarkerHandle) != ERROR_SUCCESS) {
        std::cerr << "Failed to create walk marker. Error: " << GetLastError() << std::endl;
        return;
    }

    PSS_AUXILIARY_PAGE_ENTRY pageEntry = { 0 };
    while (PssWalkSnapshot(hSnapshot, PSS_WALK_AUXILIARY_PAGES, walkMarkerHandle, &pageEntry, sizeof(pageEntry)) == ERROR_SUCCESS) {
        std::cout << "PssWalkSnapshot  with PSS_WALK_AUXILIARY_PAGES success" << std::endl;
        std::cout << "Auxiliary Page Address: " << pageEntry.Address << std::endl;
        std::cout << "Page Capture Time: " << pageEntry.CaptureTime.dwLowDateTime << std::endl; // FILETIME need convertion but i cant get here even
        std::cout << "Page Size: " << pageEntry.PageSize << std::endl;

        if (pageEntry.PageContents != NULL) {
            std::cout << "Page Contents available." << std::endl;
            // Process dump without a MiniDumpWriteDump callback?
        }
        else {
            std::cout << "Page Contents not available." << std::endl;
        }

        ZeroMemory(&pageEntry, sizeof(pageEntry)); // Reset for the next iteration
    }

    if (walkMarkerHandle) {
        PssWalkMarkerFree(walkMarkerHandle); // Clean up the walk marker
    }
}
void DisplayVASpace(HPSS hSnapshot) {
    HPSSWALK walkMarkerHandle = NULL;
    if (PssWalkMarkerCreate(NULL, &walkMarkerHandle) != ERROR_SUCCESS) {
        std::cerr << "Failed to create walk marker for VA space. Error: " << GetLastError() << std::endl;
        return;
    }

    PSS_VA_SPACE_ENTRY vaSpaceEntry = { 0 };
    while (PssWalkSnapshot(hSnapshot, PSS_WALK_VA_SPACE, walkMarkerHandle, &vaSpaceEntry, sizeof(vaSpaceEntry)) == ERROR_SUCCESS) {
        std::cout << "Base Address: " << vaSpaceEntry.BaseAddress << std::endl;
        std::cout << "Allocation Base: " << vaSpaceEntry.AllocationBase << std::endl;
        std::cout << "Allocation Protect: 0x" << std::hex << vaSpaceEntry.AllocationProtect << std::dec << std::endl;
        std::cout << "Region Size: " << vaSpaceEntry.RegionSize << std::endl;
        std::cout << "State: " << vaSpaceEntry.State << std::endl;
        std::cout << "Protect: 0x" << std::hex << vaSpaceEntry.Protect << std::dec << std::endl;
        std::cout << "Type: " << vaSpaceEntry.Type << std::endl;
        // Add more details as needed

        // Reset vaSpaceEntry for next iteration
        ZeroMemory(&vaSpaceEntry, sizeof(vaSpaceEntry));
    }

    // Clean up the walk marker
    if (walkMarkerHandle) {
        PssWalkMarkerFree(walkMarkerHandle);
    }
}

void DisplayHandleInformation(HPSS hSnapshot) {
    HPSSWALK walkMarkerHandle = NULL;
    if (PssWalkMarkerCreate(NULL, &walkMarkerHandle) != ERROR_SUCCESS) {
        std::cerr << "Failed to create walk marker for handles. Error: " << GetLastError() << std::endl;
        return;
    }

    PSS_HANDLE_ENTRY handleEntry = { 0 };
    while (PssWalkSnapshot(hSnapshot, PSS_WALK_HANDLES, walkMarkerHandle, &handleEntry, sizeof(handleEntry)) == ERROR_SUCCESS) {
        std::cout << "Handle: " << handleEntry.Handle << std::endl;
        std::cout << "Object Type: " << handleEntry.ObjectType << std::endl;
        std::cout << "Capture Time: " << std::endl; // Convert FILETIME to a readable format
        std::cout << "Attributes: " << handleEntry.Attributes << std::endl;
        std::cout << "Granted Access: " << std::hex << handleEntry.GrantedAccess << std::dec << std::endl;
        std::cout << "Handle Count: " << handleEntry.HandleCount << std::endl;
        std::cout << "Pointer Count: " << handleEntry.PointerCount << std::endl;

        if (handleEntry.Flags & PSS_HANDLE_HAVE_NAME) {
            std::wcout << L"Object Name: " << (handleEntry.ObjectName ? handleEntry.ObjectName : L"(No name)") << std::endl;
        }

        if (handleEntry.Flags & PSS_HANDLE_HAVE_TYPE) {
            std::wcout << L"Type Name: " << (handleEntry.TypeName ? handleEntry.TypeName : L"(No type)") << std::endl;

            // We can display specific information based on handleEntry.ObjectType here
            //switch (handleEntry.ObjectType) {
            //case PSS_OBJECT_TYPE_PROCESS:
            //    std::cout << "Process ID: " << handleEntry.TypeSpecificInformation.Process.ProcessId << std::endl;
            //    //...
            //    break;
            //case PSS_OBJECT_TYPE_THREAD:
            //    std::cout << "Thread ID: " << handleEntry.TypeSpecificInformation.Thread.ThreadId << std::endl;
            //    //...
            //    break;
            //}
        }

        // Would be nice to have handle trace information too but i didnt look into what is it and how it works

        // Reset handleEntry for next iteration
        ZeroMemory(&handleEntry, sizeof(handleEntry));
    }

    // Clean up the walk marker
    if (walkMarkerHandle) {
        PssWalkMarkerFree(walkMarkerHandle);
    }
}

void DisplayThreadInformation(HPSS hSnapshot) {
    HPSSWALK walkMarkerHandle = NULL;
    if (PssWalkMarkerCreate(NULL, &walkMarkerHandle) != ERROR_SUCCESS) {
        std::cerr << "Failed to create walk marker. Error: " << GetLastError() << std::endl;
        return;
    }

    PSS_THREAD_ENTRY threadEntry = { 0 };
    while (PssWalkSnapshot(hSnapshot, PSS_WALK_THREADS, walkMarkerHandle, &threadEntry, sizeof(threadEntry)) == ERROR_SUCCESS) {
        std::cout << "Thread ID: " << threadEntry.ThreadId << std::endl;
        std::cout << "Process ID: " << threadEntry.ProcessId << std::endl;
        std::cout << "Base Priority: " << threadEntry.BasePriority << std::endl;
        std::cout << "Priority: " << threadEntry.Priority << std::endl;
        std::cout << "Teb Base Address: " << threadEntry.TebBaseAddress << std::endl;
        std::cout << "Affinity Mask: " << threadEntry.AffinityMask << std::endl;
        std::cout << "Flags: " << std::hex << std::showbase << threadEntry.Flags << std::dec << std::endl;
        std::cout << "Suspend Count: " << threadEntry.SuspendCount << std::endl;
        std::cout << "Size Of Context Record: " << threadEntry.SizeOfContextRecord << std::endl;

        // For the Last Syscall Number, display only if relevant (non-zero)
        if (threadEntry.LastSyscallNumber != 0) {
            std::cout << "Last Syscall Number: " << threadEntry.LastSyscallNumber << std::endl;
            std::cout << "Last Syscall First Argument: " << threadEntry.LastSyscallFirstArgument << std::endl;
        }

        // Displaying FILETIME fields (CreateTime, ExitTime, KernelTime, UserTime, CaptureTime)
        // You might want to convert these to SYSTEMTIME or another human-readable format
        // Here is an example of how to do this conversion for CreateTime
        SYSTEMTIME st;
        if (FileTimeToSystemTime(&threadEntry.CreateTime, &st)) {
            std::cout << "Thread Create Time: ";
            std::cout << st.wYear << "-" << st.wMonth << "-" << st.wDay << " ";
            std::cout << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
        }

        std::cout << std::endl;

        // Important: Zero out the structure for the next iteration
        ZeroMemory(&threadEntry, sizeof(threadEntry));
    }

    // Clean up the walk marker
    if (walkMarkerHandle) {
        PssWalkMarkerFree(walkMarkerHandle);
    }
}

void DisplayProcessInfo(HPSS hSnapshot) {
    PSS_PROCESS_INFORMATION psinfo;
    if (PssQuerySnapshot(hSnapshot, PSS_QUERY_PROCESS_INFORMATION, &psinfo, sizeof(psinfo)) != ERROR_SUCCESS) {
        std::cout << "Failed PssQuerySnapshot: " << GetLastError() << std::endl;
        return;
    }
    
    // Print all PSS_PROCESS_INFORMATION
    std::wcout << L"Process Name: " << psinfo.ImageFileName << std::endl;
    std::cout << "Process ID: " << psinfo.ProcessId << std::endl;
    std::cout << "Parent Process ID: " << psinfo.ParentProcessId << std::endl;
    std::cout << "Base Priority: " << psinfo.BasePriority << std::endl;
    std::cout << "Page Fault Count: " << psinfo.PageFaultCount << std::endl;
    std::cout << "Working Set Size: " << psinfo.WorkingSetSize << std::endl;
    std::cout << "Peak Working Set Size: " << psinfo.PeakWorkingSetSize << std::endl;
    std::cout << "Virtual Size: " << psinfo.VirtualSize << std::endl;
    std::cout << "Peak Virtual Size: " << psinfo.PeakVirtualSize << std::endl;
    std::cout << "Pagefile Usage: " << psinfo.PagefileUsage << std::endl;
    std::cout << "Peak Pagefile Usage: " << psinfo.PeakPagefileUsage << std::endl;
    std::cout << "Private Usage: " << psinfo.PrivateUsage << std::endl;
    std::cout << "Exit Status: " << psinfo.ExitStatus << std::endl;
    std::cout << "PebBaseAddress: " << psinfo.PebBaseAddress << std::endl;
    std::cout << "Affinity Mask: " << psinfo.AffinityMask << std::endl;
    std::cout << "Priority Class: " << psinfo.PriorityClass << std::endl;
    std::cout << "Quota Peak Paged Pool Usage: " << psinfo.QuotaPeakPagedPoolUsage << std::endl;
    std::cout << "Quota Paged Pool Usage: " << psinfo.QuotaPagedPoolUsage << std::endl;
    std::cout << "Quota Peak Non-Paged Pool Usage: " << psinfo.QuotaPeakNonPagedPoolUsage << std::endl;
    std::cout << "Quota Non-Paged Pool Usage: " << psinfo.QuotaNonPagedPoolUsage << std::endl;
    std::cout << "Pagefile Usage: " << psinfo.PagefileUsage << std::endl;
    std::cout << "Peak Pagefile Usage: " << psinfo.PeakPagefileUsage << std::endl;
    std::cout << "Private Usage: " << psinfo.PrivateUsage << std::endl;
    std::cout << "Execute Flags: " << psinfo.ExecuteFlags << std::endl;

    // Displaying FILETIME structures (CreateTime, ExitTime, KernelTime, UserTime) requires conversion
    SYSTEMTIME st;
    char buffer[30];

    // CreateTime
    if (FileTimeToSystemTime(&psinfo.CreateTime, &st)) {
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::cout << "Create Time: " << buffer << std::endl;
    }

    // ExitTime
    if (FileTimeToSystemTime(&psinfo.ExitTime, &st)) {
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::cout << "Exit Time: " << buffer << std::endl;
    }

    // KernelTime
    if (FileTimeToSystemTime(&psinfo.KernelTime, &st)) {
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::cout << "Kernel Time: " << buffer << std::endl;
    }

    // UserTime
    if (FileTimeToSystemTime(&psinfo.UserTime, &st)) {
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::cout << "User Time: " << buffer << std::endl;
    }

    return;
}

void DisplayKUserSharedData(HANDLE pHandle) {
    const PVOID KUserSharedDataAddress = reinterpret_cast<PVOID>(0x7FFE0000); // 64 bit user mode 
    KUSER_SHARED_DATA kusd = { 0 };

    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(pHandle, KUserSharedDataAddress, &kusd, sizeof(kusd), &bytesRead)) {
        // Formatting all of these would probably force me to learn about each field and teach me a lot
        std::cout << "TickCountLowDeprecated: " << kusd.TickCountLowDeprecated << std::endl;
        std::cout << "TickCountMultiplier: " << kusd.TickCountMultiplier << std::endl;
        std::cout << "InterruptTime: " << kusd.InterruptTime.LowPart << ", " << kusd.InterruptTime.High1Time << std::endl;
        std::cout << "SystemTime: " << kusd.SystemTime.LowPart << ", " << kusd.SystemTime.High1Time << std::endl;
        std::cout << "TimeZoneBias: " << kusd.TimeZoneBias.LowPart << ", " << kusd.TimeZoneBias.High1Time << std::endl;
        std::cout << "ImageNumberLow: " << kusd.ImageNumberLow << std::endl;
        std::cout << "ImageNumberHigh: " << kusd.ImageNumberHigh << std::endl;
        std::wcout << "NtSystemRoot: " << kusd.NtSystemRoot << std::endl;
        std::cout << "MaxStackTraceDepth: " << kusd.MaxStackTraceDepth << std::endl;
        std::cout << "CryptoExponent: " << kusd.CryptoExponent << std::endl;
        std::cout << "TimeZoneId: " << kusd.TimeZoneId << std::endl;
        std::cout << "LargePageMinimum: " << kusd.LargePageMinimum << std::endl;
        std::cout << "AitSamplingValue: " << kusd.AitSamplingValue << std::endl;
        std::cout << "AppCompatFlag: " << kusd.AppCompatFlag << std::endl;
        std::cout << "RNGSeedVersion: " << kusd.RNGSeedVersion << std::endl;
        std::cout << "GlobalValidationRunlevel: " << kusd.GlobalValidationRunlevel << std::endl;
        std::cout << "TimeZoneBiasStamp: " << kusd.TimeZoneBiasStamp << std::endl;
        std::cout << "NtBuildNumber: " << kusd.NtBuildNumber << std::endl;
        std::cout << "NtProductType: " << kusd.NtProductType << std::endl;
        std::cout << "ProductTypeIsValid: " << static_cast<unsigned>(kusd.ProductTypeIsValid) << std::endl;
        std::cout << "Reserved0: " << static_cast<unsigned>(kusd.Reserved0[0]) << std::endl;
        std::cout << "NativeProcessorArchitecture: " << kusd.NativeProcessorArchitecture << std::endl;
        std::cout << "NtMajorVersion: " << kusd.NtMajorVersion << std::endl;
        std::cout << "NtMinorVersion: " << kusd.NtMinorVersion << std::endl;

        // is this just cpuid?
        std::cout << "ProcessorFeatures: ";
        for (int i = 0; i < 64; ++i) {
            std::cout << (kusd.ProcessorFeatures[i] ? "1" : "0");
        }
        std::cout << std::endl;

        std::cout << "Reserved1: " << kusd.Reserved1 << std::endl;
        std::cout << "Reserved3: " << kusd.Reserved3 << std::endl;
        std::cout << "TimeSlip: " << kusd.TimeSlip << std::endl;
        std::cout << "AlternativeArchitecture: " << kusd.AlternativeArchitecture << std::endl;
        std::cout << "BootId: " << kusd.BootId << std::endl;
        std::cout << "SystemExpirationDate: High: " << kusd.SystemExpirationDate.HighPart << ", Low: " << kusd.SystemExpirationDate.LowPart << std::endl;
        std::cout << "SuiteMask: " << kusd.SuiteMask << std::endl;
        std::cout << "KdDebuggerEnabled: " << static_cast<unsigned>(kusd.KdDebuggerEnabled) << std::endl;

        // MitigationPolicies and bitfields
        std::cout << "MitigationPolicies (full byte): " << static_cast<unsigned>(kusd.MitigationPolicies) << std::endl;
        std::cout << "NXSupportPolicy (bits 0-1): " << static_cast<unsigned>(kusd.NXSupportPolicy) << std::endl;
        std::cout << "SEHValidationPolicy (bits 2-3): " << static_cast<unsigned>(kusd.SEHValidationPolicy) << std::endl;
        std::cout << "CurDirDevicesSkippedForDlls (bits 4-5): " << static_cast<unsigned>(kusd.CurDirDevicesSkippedForDlls) << std::endl;
        std::cout << "Reserved (bits 6-7): " << static_cast<unsigned>((kusd.MitigationPolicies >> 6) & 0x03) << std::endl;

        std::cout << "CyclesPerYield: " << kusd.CyclesPerYield << std::endl;
        std::cout << "ActiveConsoleId: " << kusd.ActiveConsoleId << std::endl;
        std::cout << "DismountCount: " << kusd.DismountCount << std::endl;
        std::cout << "ComPlusPackage: " << kusd.ComPlusPackage << std::endl;
        std::cout << "LastSystemRITEventTickCount: " << kusd.LastSystemRITEventTickCount << std::endl;
        std::cout << "NumberOfPhysicalPages: " << kusd.NumberOfPhysicalPages << std::endl;
        std::cout << "SafeBootMode: " << static_cast<unsigned>(kusd.SafeBootMode) << std::endl;
        std::cout << "VirtualizationFlags: " << static_cast<unsigned>(kusd.VirtualizationFlags) << std::endl;
        std::cout << "Reserved12: " << kusd.Reserved12 << std::endl;

        // SharedDataFlags and bitfields
        std::cout << "SharedDataFlags: " << kusd.SharedDataFlags << std::endl;
        std::cout << "DbgErrorPortPresent: " << ((kusd.SharedDataFlags >> 0) & 1) << std::endl;
        std::cout << "DbgElevationEnabled: " << ((kusd.SharedDataFlags >> 1) & 1) << std::endl;
        std::cout << "DbgVirtEnabled: " << ((kusd.SharedDataFlags >> 2) & 1) << std::endl;
        std::cout << "DbgInstallerDetectEnabled: " << ((kusd.SharedDataFlags >> 3) & 1) << std::endl;
        std::cout << "DbgLkgEnabled: " << ((kusd.SharedDataFlags >> 4) & 1) << std::endl;
        std::cout << "DbgDynProcessorEnabled: " << ((kusd.SharedDataFlags >> 5) & 1) << std::endl;
        std::cout << "DbgConsoleBrokerEnabled: " << ((kusd.SharedDataFlags >> 6) & 1) << std::endl;
        std::cout << "DbgSecureBootEnabled: " << ((kusd.SharedDataFlags >> 7) & 1) << std::endl;
        std::cout << "DbgMultiSessionSku: " << ((kusd.SharedDataFlags >> 8) & 1) << std::endl;
        std::cout << "DbgMultiUsersInSessionSku: " << ((kusd.SharedDataFlags >> 9) & 1) << std::endl;
        std::cout << "DbgStateSeparationEnabled: " << ((kusd.SharedDataFlags >> 10) & 1) << std::endl;
        std::cout << "SpareBits: " << ((kusd.SharedDataFlags >> 11) & 0x1FFFFF) << std::endl; // Use mask 0x1FFFFF to get 21 bits

        std::cout << "TestRetInstruction: " << kusd.TestRetInstruction << std::endl;
        std::cout << "QpcFrequency: " << kusd.QpcFrequency << std::endl;
        std::cout << "SystemCall: " << kusd.SystemCall << std::endl;
        std::cout << "Reserved2: " << kusd.Reserved2 << std::endl;
        std::cout << "SystemCallPad: [" << kusd.SystemCallPad[0] << ", " << kusd.SystemCallPad[1] << "]" << std::endl;
        std::cout << "TickCount (LowPart): " << kusd.TickCount.LowPart << std::endl;
        std::cout << "TickCount (High1Time): " << kusd.TickCount.High1Time << std::endl;
        std::cout << "TickCountQuad: " << kusd.TickCountQuad << std::endl;
        std::cout << "TickCountPad: " << kusd.TickCountPad[0] << std::endl;
        std::cout << "Cookie: " << kusd.Cookie << std::endl;
        std::cout << "CookiePad: " << kusd.CookiePad[0] << std::endl;
        std::cout << "ConsoleSessionForegroundProcessId: " << kusd.ConsoleSessionForegroundProcessId << std::endl;
        std::cout << "TimeUpdateLock: " << kusd.TimeUpdateLock << std::endl;
        std::cout << "BaselineSystemTimeQpc: " << kusd.BaselineSystemTimeQpc << std::endl;
        std::cout << "BaselineInterruptTimeQpc: " << kusd.BaselineInterruptTimeQpc << std::endl;
        std::cout << "QpcSystemTimeIncrement: " << kusd.QpcSystemTimeIncrement << std::endl;
        std::cout << "QpcInterruptTimeIncrement: " << kusd.QpcInterruptTimeIncrement << std::endl;
        std::cout << "QpcSystemTimeIncrementShift: " << static_cast<unsigned>(kusd.QpcSystemTimeIncrementShift) << std::endl;
        std::cout << "QpcInterruptTimeIncrementShift: " << static_cast<unsigned>(kusd.QpcInterruptTimeIncrementShift) << std::endl;
        std::cout << "UnparkedProcessorCount: " << kusd.UnparkedProcessorCount << std::endl;

        // Displaying EnclaveFeatureMask as an array
        std::cout << "EnclaveFeatureMask: [";
        for (int i = 0; i < 4; ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << kusd.EnclaveFeatureMask[i];
        }
        std::cout << "]" << std::endl;

        std::cout << "TelemetryCoverageRound: " << kusd.TelemetryCoverageRound << std::endl;

        // Displaying UserModeGlobalLogger as an array
        std::cout << "UserModeGlobalLogger: [";
        for (int i = 0; i < 16; ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << kusd.UserModeGlobalLogger[i];
        }
        std::cout << "]" << std::endl;

        std::cout << "ImageFileExecutionOptions: " << kusd.ImageFileExecutionOptions << std::endl;
        std::cout << "LangGenerationCount: " << kusd.LangGenerationCount << std::endl;
        std::cout << "Reserved4: " << kusd.Reserved4 << std::endl;
        std::cout << "InterruptTimeBias: " << kusd.InterruptTimeBias << std::endl;
        std::cout << "QpcBias: " << kusd.QpcBias << std::endl;
        std::cout << "ActiveProcessorCount: " << kusd.ActiveProcessorCount << std::endl;
        std::cout << "ActiveGroupCount: " << static_cast<unsigned>(kusd.ActiveGroupCount) << std::endl;
        std::cout << "Reserved9: " << static_cast<unsigned>(kusd.Reserved9) << std::endl;
        std::cout << "QpcData: " << kusd.QpcData << std::endl;
        std::cout << "QpcBypassEnabled: " << static_cast<unsigned>(kusd.QpcBypassEnabled) << std::endl;
        std::cout << "QpcShift: " << static_cast<unsigned>(kusd.QpcShift) << std::endl;
        std::cout << "TimeZoneBiasEffectiveStart: " << kusd.TimeZoneBiasEffectiveStart.QuadPart << std::endl;
        std::cout << "TimeZoneBiasEffectiveEnd: " << kusd.TimeZoneBiasEffectiveEnd.QuadPart << std::endl;
        std::cout << "XState.EnabledFeatures: " << kusd.XState.EnabledFeatures << std::endl;
        std::cout << "FeatureConfigurationChangeStamp: " << kusd.FeatureConfigurationChangeStamp.LowPart << ", " << kusd.FeatureConfigurationChangeStamp.High1Time << std::endl;
        std::cout << "Spare: " << kusd.Spare << std::endl;
        std::cout << "UserPointerAuthMask: " << kusd.UserPointerAuthMask << std::endl;
    }
    else {
        std::cerr << "Failed to read memory. Error: " << GetLastError() << std::endl;
    }
}
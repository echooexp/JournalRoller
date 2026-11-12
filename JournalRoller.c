#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>
#include <time.h>

#define READ_BUF_SIZE (1024 * 1024)

static void EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = { 0 };
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    if (LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

static void InitConsole(void) {
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
            SetConsoleMode(hOut, mode);
        }
    }
}

static void ReadLine(wchar_t* buffer, int maxLen) {
    if (!fgetws(buffer, maxLen, stdin)) {
        buffer[0] = L'\0';
        return;
    }
    size_t len = wcslen(buffer);
    while (len > 0 && (buffer[len - 1] == L'\n' || buffer[len - 1] == L'\r')) {
        buffer[--len] = L'\0';
    }
}

static void ExecuteRoll(wchar_t driveLetter, const wchar_t* target) {
    wchar_t volPath[32];
    swprintf_s(volPath, 32, L"\\\\.\\%c:", driveLetter);

    HANDLE hVol = CreateFileW(
        volPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hVol == INVALID_HANDLE_VALUE) {
        wprintf(L"\033[91m[-] Failed to open volume %c: (error %lu). Run as Administrator.\033[0m\n", driveLetter, GetLastError());
        return;
    }

    USN_JOURNAL_DATA_V0 ujd = { 0 };
    DWORD returned = 0;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &ujd, sizeof(ujd), &returned, NULL)) {
        wprintf(L"\033[91m[-] FSCTL_QUERY_USN_JOURNAL failed (error %lu).\033[0m\n", GetLastError());
        CloseHandle(hVol);
        return;
    }

    wprintf(L"\033[94m[*] Scanning %c: for '%s'...\033[0m\n", driveLetter, target);

    BYTE* buf = (BYTE*)VirtualAlloc(NULL, READ_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        CloseHandle(hVol);
        return;
    }

    READ_USN_JOURNAL_DATA_V0 ruj = { 0 };
    ruj.StartUsn = ujd.FirstUsn;
    ruj.ReasonMask = 0xFFFFFFFF;
    ruj.UsnJournalID = ujd.UsnJournalID;

    USN highestUsn = 0;
    LONGLONG matches = 0;
    size_t targetLen = wcslen(target);

    for (;;) {
        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &ruj, sizeof(ruj), buf, READ_BUF_SIZE, &bytesRet, NULL);
        if (!ok || bytesRet < sizeof(USN)) break;

        USN nextCursor = *(USN*)buf;
        ruj.StartUsn = nextCursor;

        BYTE* p = buf + sizeof(USN);
        BYTE* end = buf + bytesRet;

        while (p + sizeof(USN_RECORD_V2) <= end) {
            USN_RECORD_V2* rec = (USN_RECORD_V2*)p;
            if (rec->RecordLength == 0 || p + rec->RecordLength > end) break;

            WCHAR fname[MAX_PATH] = { 0 };
            WORD fnBytes = min(rec->FileNameLength, (WORD)((MAX_PATH - 1) * sizeof(WCHAR)));
            if (fnBytes > 0 && (DWORD)(rec->FileNameOffset + fnBytes) <= rec->RecordLength) {
                memcpy(fname, (BYTE*)rec + rec->FileNameOffset, fnBytes);
            }

            if (_wcsicmp(fname, target) == 0 || _wcsnicmp(fname, target, targetLen) == 0) {
                matches++;
                if (rec->Usn > highestUsn) {
                    highestUsn = rec->Usn;
                }
            }
            p += rec->RecordLength;
        }

        if (nextCursor == ruj.StartUsn && bytesRet == sizeof(USN)) break;
    }

    VirtualFree(buf, 0, MEM_RELEASE);

    if (highestUsn == 0) {
        wprintf(L"\033[92m[+] Clean: No active records found for '%s'.\033[0m\n", target);
        CloseHandle(hVol);
        return;
    }

    LONGLONG distanceToRoll = highestUsn - ujd.FirstUsn;
    wprintf(L"\033[94m[*] Found %lld match(es). Highest USN: 0x%016llX\033[0m\n", matches, highestUsn);
    wprintf(L"\033[94m[*] FirstUSN: 0x%016llX | NextUSN: 0x%016llX | Distance: ~%.2f MB\033[0m\n",
        ujd.FirstUsn, ujd.NextUsn, (double)distanceToRoll / (1024.0 * 1024.0));
    wprintf(L"\033[94m[*] Fast rolling journal forward...\033[0m\n");

    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    wchar_t f1[MAX_PATH], f2[MAX_PATH];
    swprintf_s(f1, MAX_PATH, L"%s\\usn_fast_%lu_a.tmp", tempDir, GetCurrentProcessId());
    swprintf_s(f2, MAX_PATH, L"%s\\usn_fast_%lu_b.tmp", tempDir, GetCurrentProcessId());

    HANDLE hInit = CreateFileW(f1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hInit != INVALID_HANDLE_VALUE) CloseHandle(hInit);

    clock_t startTime = clock();

    while (ujd.FirstUsn <= highestUsn) {
        for (int i = 0; i < 400; i++) {
            MoveFileExW(f1, f2, MOVEFILE_REPLACE_EXISTING);
            MoveFileExW(f2, f1, MOVEFILE_REPLACE_EXISTING);
        }

        if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &ujd, sizeof(ujd), &returned, NULL)) {
            break;
        }

        double elapsed = (double)(clock() - startTime) / CLOCKS_PER_SEC;
        LONGLONG remaining = (highestUsn > ujd.FirstUsn) ? (highestUsn - ujd.FirstUsn) : 0;
        wprintf(L"\r\033[94m[*] Rolling: FirstUSN=0x%016llX | Remaining: %lld KB (%.1fs)\033[0m   ",
            ujd.FirstUsn, remaining / 1024, elapsed);
        fflush(stdout);
    }

    DeleteFileW(f1);
    DeleteFileW(f2);

    double totalTime = (double)(clock() - startTime) / CLOCKS_PER_SEC;
    wprintf(L"\n\033[92m[+] Done in %.2fs! '%s' successfully rolled out of the journal.\033[0m\n", totalTime, target);
    wprintf(L"\033[92m[+] New FirstUSN: 0x%016llX (> 0x%016llX)\033[0m\n", ujd.FirstUsn, highestUsn);
    wprintf(L"\033[92m[+] UsnJournalID: 0x%016llX (preserved, passes bypass checks)\033[0m\n", ujd.UsnJournalID);

    CloseHandle(hVol);
}

int wmain(int argc, wchar_t* argv[]) {
    InitConsole();

    EnablePrivilege(SE_BACKUP_NAME);
    EnablePrivilege(SE_RESTORE_NAME);
    EnablePrivilege(SE_MANAGE_VOLUME_NAME);

    if (argc >= 2) {
        wchar_t driveLetter = L'C';
        const wchar_t* target = argv[1];
        if (argc >= 3) {
            driveLetter = (wchar_t)towupper(argv[1][0]);
            target = argv[2];
        }
        ExecuteRoll(driveLetter, target);
        return 0;
    }

    wchar_t targetInput[MAX_PATH];
    for (;;) {
        wprintf(L"\n\033[94m[?] Enter filename to roll out (or 'exit'): \033[0m");
        ReadLine(targetInput, MAX_PATH);

        if (targetInput[0] == L'\0') continue;
        if (_wcsicmp(targetInput, L"exit") == 0 || _wcsicmp(targetInput, L"q") == 0) break;

        ExecuteRoll(L'C', targetInput);
    }

    wprintf(L"\033[92m[+] Exited.\033[0m\n");
    return 0;
}

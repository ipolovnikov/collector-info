#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <winsock2.h>
#include <VersionHelpers.h> //os
#include <ws2tcpip.h> //ip
#include <tlhelp32.h> // process

#define INFO_BUFFER_SIZE 32767

BOOL Is64BitWindows()
{
    #if defined(_WIN64)
        return TRUE;  // 64-bit programs run only on Win64
    #elif defined(_WIN32)
        // 32-bit programs run on both 32-bit and 64-bit Windows
        // so must sniff
        BOOL f64 = FALSE;
        return IsWow64Process(GetCurrentProcess(), &f64) && f64;
    #else
        return FALSE; // Win64 does not support Win16
    #endif
}

VOID PrintModuleList(HANDLE CONST hStdOut, DWORD CONST dwProcessId) {
  MODULEENTRY32 meModuleEntry;
  TCHAR szBuff[1024];
  DWORD dwTemp;
  HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
  if(INVALID_HANDLE_VALUE == hSnapshot) {
    return;
  }

  meModuleEntry.dwSize = sizeof(MODULEENTRY32);
  Module32First(hSnapshot, &meModuleEntry);

  do {
    wsprintf(szBuff, "  ba: %08X, bs: %08X, %s\r\n",
             meModuleEntry.modBaseAddr,
             meModuleEntry.modBaseSize,
             meModuleEntry.szModule
            );
    WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
  } while(Module32Next(hSnapshot, &meModuleEntry));

  CloseHandle(hSnapshot);
}

VOID PrintProcessList(HANDLE CONST hStdOut) {
  PROCESSENTRY32 peProcessEntry;
  TCHAR szBuff[1024];
  DWORD dwTemp;
  HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
                             TH32CS_SNAPPROCESS, 0);
  if(INVALID_HANDLE_VALUE == hSnapshot) {
    return;
  }

  peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
  Process32First(hSnapshot, &peProcessEntry);
  do {
    wsprintf(szBuff, "=== %08X (%08X) %s ===\r\n",
             peProcessEntry.th32ProcessID,
             peProcessEntry.th32ParentProcessID,
             peProcessEntry.szExeFile
            );
    WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
    PrintModuleList(hStdOut, peProcessEntry.th32ProcessID);
  } while(Process32Next(hSnapshot, &peProcessEntry));

  CloseHandle(hSnapshot);
}

int main(int argc, char **argv)
{
    DWORD i;
    TCHAR infoBuf[INFO_BUFFER_SIZE];
    DWORD bufCharCount = INFO_BUFFER_SIZE;

    // Імя комп'ютера
    bufCharCount = INFO_BUFFER_SIZE;
    GetComputerName( infoBuf, &bufCharCount );
    printf("ComputerName: %s\n", infoBuf);

    // Імя користувача
    bufCharCount = INFO_BUFFER_SIZE;
    GetUserName( infoBuf, &bufCharCount );
    printf("UserName: %s\n", infoBuf);

    // Версія ОС
    bufCharCount = ExpandEnvironmentStrings(TEXT("OS: %OS%"), infoBuf, INFO_BUFFER_SIZE);
    if( bufCharCount < INFO_BUFFER_SIZE && bufCharCount )
        printf("%s (v: %d, ex: %d) ", infoBuf, GetVersion(), GetVersionEx);

    // Розрядність ОС
    if (Is64BitWindows())
        printf("x64\n");
    else printf("x32\n");

    // Імя домену
    bufCharCount = INFO_BUFFER_SIZE;
    GetComputerNameEx(ComputerNameDnsDomain, infoBuf, &bufCharCount);
    if (!bufCharCount) {
        printf("ComputerNameDnsDomain: computer is in a workgroup\n", infoBuf);
    } else printf("ComputerNameDnsDomain: %s\n", infoBuf);

    // IP адреса/и
    WSADATA ws;
    int res;
    // Initializing winsock
    // Before using any of the winsock constructs, the library must be initialized by calling the WSAStartup function.
    res = WSAStartup ( MAKEWORD(2, 2), &ws );
    if ( res != 0 )
    {
        //cout << "Failed to initialize winsock : " << res;
        return 1;
    }

    char * hostname;
    struct hostent * host_info;
    struct in_addr addr;
    DWORD dw;
    i = 0;

    hostname = (char *)"localhost"; // hostname for which we want the IP address

    // gethostbyname function retrieves host information.
    // gethostbyname returns a pointer of type struct hostent.
    // A null pointer is returned if an error occurs. The specific error number can be known by calling WSAGetLastError.
    if ((host_info = gethostbyname ( hostname )) == NULL)
    {
        dw = WSAGetLastError ();
        if ( dw != 0 )
        {
            if ( dw == WSAHOST_NOT_FOUND )
            {
                printf("Host is not found");
                return 1;
            }
            else if ( dw == WSANO_DATA )
            {
                printf("No data record is found");
                return 1;
            }
            else
            {
                printf("Function failed with an error");
                return 1;
            }
        }
    }
    else
    {
        printf("Hostname: %s\n", host_info->h_name);
        while ( host_info->h_addr_list[i] != 0 )
        {
            addr.s_addr = *(u_long *) host_info->h_addr_list[i++];
            printf("IP Address: %s\n", inet_ntoa(addr)); // inet_ntoa function converts IPv4 address to ASCII string in Internet standard dotted-decimal format.
        }
    }

    // Список жорстких дисків
    BOOL bFlag;
    TCHAR Buf[MAX_PATH];           // temporary buffer for volume name
    TCHAR Drive[] = TEXT("c:\\"); // template drive specifier
    TCHAR I;                      // generic loop counter

    // Walk through legal drive letters, skipping floppies.
    for (I = TEXT('c'); I < TEXT('z');  I++ )
    {
        // Stamp the drive for the appropriate letter.
        Drive[0] = I;

        bFlag = GetVolumeNameForVolumeMountPoint(
                    Drive,     // input volume mount point or directory
                    Buf,       // output volume name buffer
                    MAX_PATH ); // size of volume name buffer

        if (bFlag)
        {
            _tprintf (TEXT("\"%s\" \"%s\"\n"), Drive, Buf);
        }
    }

    // Список всіх процесів (імя процесу, PID процесу, PID батьківського процесу)
    HANDLE CONST hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    PrintProcessList(hStdOut);



    return 0;
}

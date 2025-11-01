#include "resource.h"
#include <Windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <shellscalingapi.h>
#pragma comment(lib, "Shcore.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")


#define IOCTL_GET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

HWND g_hDlg = NULL;
HWND g_hLog = NULL;
LPWSTR g_szDriverPath = NULL;

typedef struct _DATA_PROCESS {
    HANDLE pid;
} DATA_PROCESS, *PDATA_PROCESS;


static void Log(LPCWSTR lpLog)
{
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_REPLACESEL, (WPARAM)FALSE, (LPARAM)lpLog);
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void HideProcess()
{
    HANDLE hDev = NULL;
    DATA_PROCESS pProcess = { 0 };
    DWORD  bytesReturned = 0;
    BOOL   ok;

    hDev = CreateFile(L"\\\\.\\ProcessHiderCore",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hDev == INVALID_HANDLE_VALUE)
    {
        wchar_t buf[MAX_PATH];
        swprintf(buf, MAX_PATH, L"[-]CreateFile 失败: %lu\r\n", GetLastError());
        Log(buf);
    }

    DWORD dwPid;
    wchar_t pidBuf[MAX_PATH];
    GetDlgItemTextW(g_hDlg, IDC_EDIT_PID, pidBuf, MAX_PATH);
    dwPid = _wtoi(pidBuf);
    if (!dwPid || dwPid > 65535)
    {
        Log(L"[-]请输入正确的PID\r\n");
        CloseHandle(hDev);
        return;
    }

    pProcess.pid = (HANDLE)(ULONG_PTR)dwPid;
    ok = DeviceIoControl(hDev,
        IOCTL_GET_PID,
        &pProcess, sizeof(pProcess),
        &pProcess, sizeof(pProcess),
        &bytesReturned, NULL
    );

    if (!ok)
    {
        wchar_t buf[MAX_PATH];
        swprintf(buf, MAX_PATH, L"[-]DeviceIoControl 失败: %lu\r\n", GetLastError());
        Log(buf);
        CloseHandle(hDev);
        return;
    }

    wchar_t LogBuf[MAX_PATH];
    swprintf(LogBuf, MAX_PATH, L"[+]已隐藏进程 PID: %lu\r\n", dwPid);
    Log(LogBuf);

    CloseHandle(hDev);
}

static BOOL GetDriverFullPath(LPCWSTR szSysName, LPWSTR bufOut)
{
    WCHAR szDir[MAX_PATH];

    if (!GetModuleFileNameW(NULL, szDir, MAX_PATH))
        return FALSE;
    PathRemoveFileSpecW(szDir);

    return PathCombineW(bufOut, szDir, szSysName) != NULL;
}

static BOOL LoadDriver(LPCWSTR szSvcName, LPCWSTR szSysPath)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL      bOk = FALSE;
    DWORD     err;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        wchar_t buf[MAX_PATH];
        swprintf(buf, MAX_PATH, L"[-]OpenSCManager 失败: %lu\r\n", GetLastError());
        Log(buf);
        return FALSE;
    }

    hSvc = CreateServiceW(
        hSCM,
        szSvcName, szSvcName, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, szSysPath,
        NULL, NULL, NULL, NULL, NULL
    );

    err = GetLastError();
    if (hSvc == NULL && err == ERROR_SERVICE_EXISTS)
    {
        hSvc = OpenServiceW(hSCM, szSvcName, SERVICE_ALL_ACCESS);
        err = hSvc ? ERROR_SUCCESS : GetLastError();
    }

    if (hSvc == NULL)
    {
        wchar_t buf[MAX_PATH];
        swprintf(buf, MAX_PATH, L"[-]CreateService/OpenService 失败: %lu\r\n", err);
        Log(buf);
        goto Cleanup;
    }

    if (!StartServiceW(hSvc, 0, NULL))
    {
        err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            Log(L"[*]驱动正在运行\r\n");
            bOk = TRUE;
        }
        else
        {
            wchar_t buf[MAX_PATH];
            swprintf(buf, MAX_PATH, L"[-]StartService 失败: %lu\r\n", err);
            Log(buf);
        }
    }
    else
    {
        Log(L"[+]驱动加载成功\r\n");
        bOk = TRUE;
    }

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return bOk;
}

static BOOL UnLoadDriver(LPCWSTR szSvcName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hSCM, szSvcName, SERVICE_ALL_ACCESS);
    if (hSvc)
    {
        SERVICE_STATUS ss;
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    return TRUE;
}

static ULONG_PTR CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
        g_hDlg = hDlg;
        g_hLog = GetDlgItem(hDlg, IDC_LOG);
        if (LoadDriver(L"ProcessHiderCore", g_szDriverPath))
            EnableWindow(GetDlgItem(g_hDlg, IDC_BUT_HIDE), TRUE);
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BUT_HIDE)
            HideProcess();
        break;
    case WM_CLOSE:
        UnLoadDriver(L"ProcessHiderCore");
        EndDialog(hDlg, 0);
        break;
    default:
        DefWindowProc(hDlg, uMsg, wParam, lParam);
        break;
    }
    return TRUE;
}


int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nShowCmd)
{
    SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);

    WCHAR driverPath[MAX_PATH] = { 0 };
    GetDriverFullPath(L"ProcessHiderCore.sys", driverPath);
    g_szDriverPath = driverPath;
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)DlgProc);
    return 0;
}
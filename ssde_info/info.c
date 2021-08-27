#pragma warning (disable : 4514 4710 4711)
#pragma warning (push)
#pragma warning (disable : 4668 4820)

#define     UNICODE
#define     WIN32_LEAN_AND_MEAN 1
#include    <windows.h>
#include    <winioctl.h>
#include    <stdio.h>
#pragma warning (pop)
#include "../common.h"

WCHAR const DeviceName[] = L"\\\\.\\" SSDE_DEVICE_NAME;

int __cdecl wmain(void)
{
    DWORD ec;

    printf("\n");

    HANDLE device = CreateFile(
        DeviceName,
        0,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (device == INVALID_HANDLE_VALUE) {
        ec = GetLastError();
        printf("Error 0x%08X opening device %ws", (UINT32)ec, DeviceName);
    }
    else {

        printf("Device %ws is present\n", DeviceName);

        SSDE_API_INFO info;
        ULONG cb;
        BOOL ok = DeviceIoControl(
            device,
            IOCTL_SELFSIGN_GET_VERSION,
            NULL,
            0,
            &info,
            sizeof(info),
            &cb,
            NULL);
        if (!ok) {
            ec = GetLastError();
            printf("Error 0x%08X getting version", (UINT32)ec);
        }
        else if (cb != sizeof(info)) {
            printf("API version unknown");
            ec = ERROR_INVALID_DATA;
        }
        else {
            printf("API version is %u.%u\n", info.Major, info.Minor);
            printf("Arm count is %lu\n", info.ArmCount);
            printf("Arm watchdog status is %lu\n", info.Status);
            printf("License tamper state is %lu", info.TamperState);
            ec = ERROR_SUCCESS;
        }

        CloseHandle(device);
    }
    printf("\n");
    return (int)ec;
}
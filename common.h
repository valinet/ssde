#ifndef _H_COMMON_H_
#define _H_COMMON_H_

#define SSDE_DEVICE_NAME            L"SSDE"

#define SSDE_API_MAJOR_VERSION      1
#define SSDE_API_MINOR_VERSION      1

#define FILE_DEVICE_SELFSIGN            FILE_DEVICE_UNKNOWN

#define SSDE_CTL_CODE(func) \
    CTL_CODE (FILE_DEVICE_SELFSIGN, (func), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SELFSIGN_GET_VERSION      SSDE_CTL_CODE (0)

#define PRODUCT_OPTIONS_STR L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
#define PRODUCT_POLICY_STR L"ProductPolicy"

typedef struct SSDE_API_INFO
{
    USHORT Minor;
    USHORT Major;
    ULONG ArmCount;
    ULONG Status;
    ULONG TamperState;
} SSDE_API_INFO;

typedef struct _PPBinaryHeader {
    ULONG TotalSize;
    ULONG DataSize;
    ULONG EndMarkerSize;
    ULONG Reserved;
    ULONG Revision;
} PPBinaryHeader, * PPPBinaryHeader;

typedef struct _PPBinaryValue {
    USHORT TotalSize;
    USHORT NameSize;
    USHORT DataType;
    USHORT DataSize;
    ULONG Flags;
    ULONG Reserved;
} PPBinaryValue, * PPPBinaryValue;

#pragma code_seg ("PAGE")
FORCEINLINE
LONG HandlePolicyBinary(
    _In_ ULONG cbBytes,
    _In_ PUCHAR lpBytes,
    _In_ PULONG uEdit
)
{
    BOOLEAN AllowConfigurablePolicyCustomKernelSignerSet = FALSE;
    PPPBinaryHeader pHeader = (PPPBinaryHeader)lpBytes;
    PUCHAR EndPtr = lpBytes + cbBytes;
    PPPBinaryValue pVal;

    if (cbBytes < sizeof(PPBinaryHeader) ||
        cbBytes != pHeader->TotalSize ||
        cbBytes != sizeof(PPBinaryHeader) + sizeof(ULONG) + pHeader->DataSize)
    {
        return 0xC0000004L;
    }

    EndPtr -= sizeof(ULONG);
    if (*(PULONG)EndPtr != 0x45)    // Product policy end-mark
        return STATUS_INVALID_PARAMETER;

    for (pVal = (PPPBinaryValue)(pHeader + 1); (PUCHAR)pVal + sizeof(PPBinaryValue) < EndPtr; pVal = (PPPBinaryValue)((PUCHAR)pVal + pVal->TotalSize)) {
        PWSTR pValName;
        PVOID pValData;

        if (pVal->NameSize % 2 != 0)
            return STATUS_INVALID_PARAMETER;

        pValName = (PWSTR)(pVal + 1);
        pValData = (PUCHAR)pValName + pVal->NameSize;

        if ((PUCHAR)pValData + pVal->DataSize > EndPtr)
            return STATUS_INVALID_PARAMETER;

        if (AllowConfigurablePolicyCustomKernelSignerSet == FALSE && _wcsnicmp(pValName, L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners", pVal->NameSize / 2) == 0) {
            if (pVal->DataType == REG_DWORD && pVal->DataSize == 4) {
                if (*uEdit)
                {
                    *(PULONG)pValData = *uEdit;
                    *uEdit = 0;
                }
                else
                {
                    *uEdit = *(PULONG)pValData;
                }
                AllowConfigurablePolicyCustomKernelSignerSet = TRUE;
                break;
            }
            else {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    return 0;
}
#pragma code_seg ()
#endif
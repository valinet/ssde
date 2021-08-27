#include <Windows.h>
#include <stdio.h>
#include "../common.h"

int main()
{
    BOOL bOk = FALSE;
    HKEY hKey;
    if (RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        PRODUCT_OPTIONS_STR,
        0,
        KEY_READ,
        &hKey
    ) == ERROR_SUCCESS)
    {
        LPDWORD ResultLength = 0;
        if (RegGetValueW(
            hKey,
            NULL,
            PRODUCT_POLICY_STR,
            RRF_RT_REG_BINARY,
            NULL,
            NULL,
            &ResultLength
        ) == ERROR_SUCCESS)
        {
            void* buffer = malloc(ResultLength);
            if (buffer)
            {
                if (RegGetValueW(
                    hKey,
                    NULL,
                    PRODUCT_POLICY_STR,
                    RRF_RT_REG_BINARY,
                    NULL,
                    buffer,
                    &ResultLength
                ) == ERROR_SUCCESS)
                {
                    ULONG uEdit = 0;
                    HandlePolicyBinary(
                        ResultLength,
                        buffer,
                        &uEdit
                    );
                    printf("%lu\n", uEdit);
                    bOk = TRUE;
                }
                free(buffer);
            }
        }
    }
    if (!bOk)
    {
        printf("%ld\n", -1);
    }
    return 0;
}
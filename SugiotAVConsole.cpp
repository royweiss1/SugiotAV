#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#define IOCTL_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WHITELIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLOCK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

void PrintUsage()
{
    printf("Usage:\n");
    printf("  SugiotAVconsole.exe -blacklist <filename.exe>\n");
    printf("  SugiotAVconsole.exe -whitelist <filename.exe>\n");
    printf("  SugiotAVconsole.exe -block <filename>\n");
    printf("  SugiotAVconsole.exe -dump <pid> -size <n> -file <dumpfile>\n");
    printf("  SugiotAVconsole.exe -kill <pid>\n");
    printf("  SugiotAVconsole.exe -init\n");
}

BOOL SendIoControl(HANDLE hDevice, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferSize, PVOID OutputBuffer, DWORD OutputBufferSize)
{
    DWORD bytesReturned;
    return DeviceIoControl(
        hDevice,
        IoControlCode,
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        &bytesReturned,
        NULL
    );
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    HANDLE hDevice = CreateFile(
        L"\\\\.\\sugiotAVLink",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open device: %ld\n", GetLastError());
        return 1;
    }

    if (strcmp(argv[1], "-blacklist") == 0 && argc == 3)
    {
        printf("Block command sent successfully.\n");
        if (SendIoControl(hDevice, IOCTL_BLACKLIST, argv[2], (DWORD)strlen(argv[2]) + 1, NULL, 0))
        {
            printf("Blacklist command sent successfully.\n");
        }
        else
        {
            printf("Failed to send blacklist command.\n");
        }
    }
    else if (strcmp(argv[1], "-whitelist") == 0 && argc == 3)
    {
        if (SendIoControl(hDevice, IOCTL_WHITELIST, argv[2], (DWORD)strlen(argv[2]) + 1, NULL, 0))
        {
            printf("Whitelist command sent successfully.\n");
        }
        else
        {
            printf("Failed to send whitelist command.\n");
        }
    }
    else if (strcmp(argv[1], "-block") == 0 && argc == 3)
    {
        const char* prefix = "\\Device\\HarddiskVolume3";
        size_t prefixLen = strlen(prefix);
        size_t argLen = strlen(argv[2]);
        size_t totalLen = prefixLen + argLen + 1; // +1 for the null terminator

        char* buffer = (char*)malloc(totalLen);
        if (buffer == NULL) {
            printf("Failed to allocate memory.\n");
            CloseHandle(hDevice);
            return 1;
        }

        strcpy_s(buffer, totalLen, prefix);
        strcat_s(buffer, totalLen, argv[2]);

        printf("Block command sent successfully.\n");

        if (SendIoControl(hDevice, IOCTL_BLOCK, buffer, (DWORD)totalLen, NULL, 0)) {
            printf("Block command sent successfully.\n");
        }
        else {
            printf("Failed to send block command.\n");
        }
    }
    else if (strcmp(argv[1], "-dump") == 0 && argc == 7)
    {
        ULONG pid = (ULONG)atoi(argv[2]);
        ULONG size = (ULONG)atoi(argv[4]);
        char* dumpfile = argv[6];
        PVOID baseAddress = (PVOID)strtoull(argv[3], NULL, 0); // Convert string to address

        typedef struct {
            ULONG pid;
            SIZE_T size;
        } MEM_DUMP_REQUEST;

        MEM_DUMP_REQUEST request;
        request.pid = pid;
        request.size = size;

        // Use VirtualAlloc instead of malloc
        PVOID buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == NULL) {
            printf("Failed to allocate memory for buffer.\n");
            return -1;
        }

        if (SendIoControl(hDevice, IOCTL_DUMP, &request, sizeof(request), buffer, size))
        {
            FILE* fp;
            errno_t err = fopen_s(&fp, dumpfile, "wb");
            if (err == 0 && fp != NULL)
            {
                printf("writing...\n");
                fwrite(buffer, 1, size, fp);
                fclose(fp);
                printf("Dump command executed successfully.\n");
            }
            else
            {
                printf("Failed to open dump file.\n");
            }
        }
        else
        {
            printf("Failed to send dump command.\n");
        }

        // Use VirtualFree instead of free
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
    else if (strcmp(argv[1], "-kill") == 0 && argc == 3)
    {
        ULONG pid = (ULONG)atoi(argv[2]);
        BOOLEAN result;

        if (SendIoControl(hDevice, IOCTL_KILL, &pid, sizeof(ULONG), &result, sizeof(BOOLEAN)))
        {
            if (result)
            {
                printf("Kill command executed successfully.\n");
            }
            else
            {
                printf("Failed to kill process.\n");
            }
        }
        else
        {
            printf("Failed to send kill command.\n");
        }
    }
    else if (strcmp(argv[1], "-init") == 0)
    {
        if (SendIoControl(hDevice, IOCTL_INIT, NULL, 0, NULL, 0))
        {
            printf("Init command sent successfully.\n");
        }
        else
        {
            printf("Failed to send init command.\n");
        }
    }
    else
    {
        PrintUsage();
    }

    CloseHandle(hDevice);
    return 0;
}

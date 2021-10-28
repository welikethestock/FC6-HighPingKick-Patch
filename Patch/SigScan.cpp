#include "SigScan.hpp"
#include <Windows.h>
#include <Psapi.h>

using SigScan::UInt64;

static
UInt64 GetModuleSize(HMODULE Module)
{
    if (Module == NULL)
    {
        return NULL;
    }

    MODULEINFO Info;
    GetModuleInformation(GetCurrentProcess(), Module, &Info, sizeof(Info));

    return Info.SizeOfImage;
}

void *SigScan::FindAddress(HMODULE Module, const byte *Pattern, const char *Mask)
{
    UInt64 StartAddress = (UInt64)Module;
    UInt64 Length = GetModuleSize(Module);

    if (StartAddress == NULL || Length == NULL)
    {
        return NULL;
    }

    size_t PatternLength = strlen(Mask);

    do
    {
        bool Found = true;
        for (size_t Index = 0; Index < PatternLength; ++Index)
        {
            if (Mask[Index] == '?')
            {
                continue;
            }

            if (*(byte *)(StartAddress + Index) != Pattern[Index])
            {
                Found = false;

                break;
            }
        }

        if (Found)
        {
            return (void *)StartAddress;
        }

        ++StartAddress;
    } while (--Length);

    return NULL;
}
#include "SigScan.hpp"
#include <Windows.h>
#include <Psapi.h>

using SigScan::UInt64;

__declspec(noinline)
PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE Module, const char *Section)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Module;
    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((UInt64)Module + DOSHeader->e_lfanew);
    if (NTHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    if (NTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        return NULL;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NTHeaders);
    for (int Index = 0; Index < NTHeaders->FileHeader.NumberOfSections; ++Index, ++SectionHeader)
    {
        if (strncmp((const char *)SectionHeader->Name, Section, 8) == 0)
        {
            return SectionHeader;
        }
    }

    return NULL;
}

__declspec(noinline)
UInt64 GetModuleSize(HMODULE Module)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Module;
    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((UInt64)Module + DOSHeader->e_lfanew);
    if (NTHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    if (NTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        return NULL;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NTHeaders);
    for (int Index = 0; Index < NTHeaders->FileHeader.NumberOfSections; ++Index, ++SectionHeader);

    return SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize;
}

void *SigScan::FindAddress(HMODULE Module, const byte *Pattern, const char *Mask, const char *Section)
{
    UInt64 StartAddress = (UInt64)Module;
    UInt64 Length = GetModuleSize(Module);

    if (Section != NULL)
    {
        PIMAGE_SECTION_HEADER SectionHeader = GetSectionHeader(Module, Section);
        if (SectionHeader != NULL)
        {
            StartAddress += SectionHeader->VirtualAddress;
            Length = SectionHeader->Misc.VirtualSize;
        }
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
    } while (--Length > 0);

    return NULL;
}
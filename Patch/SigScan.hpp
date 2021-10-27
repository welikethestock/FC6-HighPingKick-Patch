#ifndef __HEADER_SIGSCAN__
#define __HEADER_SIGSCAN__
#pragma once

#include <Windows.h>

namespace SigScan
{
    typedef UINT64 UInt64;

    __declspec(noinline)
        void *FindAddress(HMODULE Module, const byte *Pattern, const char *Mask, const char *Section = NULL);
}

#endif
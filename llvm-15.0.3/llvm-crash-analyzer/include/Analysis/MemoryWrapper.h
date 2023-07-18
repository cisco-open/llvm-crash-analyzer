
//===- MemoryWrapper.h - Track down changed memory locations ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//


#ifndef MEM_WRAPPER_H
#define MEM_WRAPPER_H

#include "Decompiler/Decompiler.h"

#include <unordered_map>

namespace llvm {
    namespace crash_analyzer {
        using MemoryValidityMap = std::unordered_map<uint64_t, std::pair<uint8_t, uint64_t> >;
        
        class MemoryWrapper{
            private:

                Decompiler* Dec = nullptr;
                MemoryValidityMap ChangedMemoryAddresses; 

            public:
                static const uint8_t NUM_OF_BYTES_PER_ADDRESS = 8;
                MemoryWrapper();
                Optional<uint64_t> ReadUnsignedFromMemory(uint64_t addr, uint32_t byte_size, lldb::SBError& error);
                void setDecompiler(Decompiler* Dec);
                void WriteMemory(uint64_t addr, const void* buf, size_t size, lldb::SBError& error);
                void InvalidateAddress(uint64_t addr, size_t size);
                void dump();
        };
    }
}

#endif
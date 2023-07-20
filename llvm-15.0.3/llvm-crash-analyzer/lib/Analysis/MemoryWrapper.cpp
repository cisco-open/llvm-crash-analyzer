//===- MemoryWrapper.cpp Track down changed memory locations --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//


#include "Analysis/MemoryWrapper.h"
#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "mem-wrapper"

// Work with write memory, maybe?

crash_analyzer::MemoryWrapper::MemoryWrapper()
{
}

//Little endian
Optional<uint64_t> crash_analyzer::MemoryWrapper::ReadUnsignedFromMemory(uint64_t addr, uint32_t byte_size, lldb::SBError& error)
{

    assert(byte_size <= 8 && "Can't read more than 8 bytes for now!");
    std::string StrVal;
    std::stringstream SS;
    uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
    uint64_t alignedAddr = addr - alignmentOffset;
    uint64_t Val = 0;


    // Only in one aligned location
    if(alignmentOffset + byte_size <= NUM_OF_BYTES_PER_ADDRESS && this->ChangedMemoryAddresses.count(alignedAddr))
    {
        uint8_t locationValidity = this->ChangedMemoryAddresses[alignedAddr].first;
        uint8_t validityMask = ((1U << byte_size) - 1) << alignmentOffset;

        uint8_t valid = (locationValidity & validityMask) ^ validityMask; 

        if(valid != 0){ 
            StrVal = "";

        LLVM_DEBUG(
            std::string AddrVal;
            SS.clear();
            SS << std::hex << addr;
            SS >> AddrVal;
            if(AddrVal.size() < 2 * 8)
            {
                AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
            }
            llvm::dbgs() << "Addressing invalid location: " << "0x" << AddrVal <<  ", byte size: " << byte_size << "\n";
            );
            return None;
        }
        else{
            Val = ((this->ChangedMemoryAddresses[alignedAddr].second & (-1UL >> (NUM_OF_BYTES_PER_ADDRESS - byte_size - alignmentOffset) * 8) )  >> (alignmentOffset * 8));
        }
    }
    else if(alignmentOffset + byte_size > NUM_OF_BYTES_PER_ADDRESS &&
            (this->ChangedMemoryAddresses.count(alignedAddr) ||
            this->ChangedMemoryAddresses.count(alignedAddr + NUM_OF_BYTES_PER_ADDRESS)))
    {
        uint8_t locationValidity1 = 0xFF;
        uint8_t locationValidity2 = 0xFF;

        if(this->ChangedMemoryAddresses.count(alignedAddr))
        {
            locationValidity1 = this->ChangedMemoryAddresses[alignedAddr].first;
        }
        if(this->ChangedMemoryAddresses.count(alignedAddr + NUM_OF_BYTES_PER_ADDRESS))
        {
            locationValidity2 = this->ChangedMemoryAddresses[alignedAddr + NUM_OF_BYTES_PER_ADDRESS].first;
        }
        uint8_t validityMask1 = ((1U << (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset)) - 1) << alignmentOffset;
        uint8_t validityMask2 = ((1U << (byte_size - (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset) - 1)));

        uint8_t valid1 = (locationValidity1 & validityMask1) ^ validityMask1;
        uint8_t valid2 = (locationValidity2 & validityMask2) ^ validityMask2;

        if(valid1 != 0 || valid2 != 0)
        { 
            StrVal = "";
            LLVM_DEBUG(
            std::string AddrVal;
            SS.clear();
            SS << std::hex << addr;
            SS >> AddrVal;
            if(AddrVal.size() < 2 * 8)
            {
                AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
            }
            llvm::dbgs() << "Addressing invalid location: " << "0x" << AddrVal <<  ", byte size: " << byte_size << "\n";
            );
            return None;
        }
        else{
            uint64_t Val1 = 0;
            if(this->ChangedMemoryAddresses.count(alignedAddr))
            {
                Val1 = this->ChangedMemoryAddresses[alignedAddr].second;
            }
            else{
                Val1 = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(alignedAddr, NUM_OF_BYTES_PER_ADDRESS, error);
            }

            uint64_t Val2 = 0;
            if(this->ChangedMemoryAddresses.count(alignedAddr + NUM_OF_BYTES_PER_ADDRESS))
            {
                Val2 = this->ChangedMemoryAddresses[alignedAddr + NUM_OF_BYTES_PER_ADDRESS].second;
            }
            else
            {
                Val2 = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(alignedAddr + NUM_OF_BYTES_PER_ADDRESS, NUM_OF_BYTES_PER_ADDRESS, error);
            }



            Val = 
            (Val1 >> (8 * alignmentOffset)) |
            (
                (
                    (Val2 & 
                    (-1UL >> (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset + NUM_OF_BYTES_PER_ADDRESS - byte_size) * 8 )) <<
                    (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset) * 8
                )
            );


        }
    }

    else if(this->Dec != nullptr){
        Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(addr, byte_size, error);
    }
    else{
        return None;
    }
    SS.clear();
    SS << std::hex << Val;
    SS >> StrVal;
    if(StrVal.size() < 2 * byte_size)
    {
        StrVal = std::string(2 * byte_size - StrVal.size(), '0') + StrVal;
    }

    
    LLVM_DEBUG(
        std::string AddrVal;
        SS.clear();
        SS << std::hex << addr;
        SS >> AddrVal;
        if(AddrVal.size() < 2 * 8)
        {
            AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
        }
        llvm::dbgs() << "Addressing valid location: " << "0x" << AddrVal <<  " : " << "0x" << StrVal << ", byte_size: " << byte_size <<"\n";
        );
    return Val;
}



void crash_analyzer::MemoryWrapper::setDecompiler(crash_analyzer::Decompiler* Dec)
{
    this->Dec = Dec;
}

void crash_analyzer::MemoryWrapper::WriteMemory(uint64_t addr, const void* buf, size_t size, lldb::SBError& error)
{
    uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
    uint64_t alignedAddr = addr - alignmentOffset;
    std::stringstream SS;
    for(uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS)
    {
        uint8_t mask = 0xFF;
        if(this->ChangedMemoryAddresses.count(alignedAddr))
        {
            mask = (0xFFU << alignmentOffset);
            if( i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset > size)
            {
                mask &= 0xFFU >> ( i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset - size);
            }
            this->ChangedMemoryAddresses[alignedAddr].first |= mask;
        }
        else{
            lldb::SBError err;
            uint64_t Val = 0;
            if(this->Dec)
            {
                Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(alignedAddr, NUM_OF_BYTES_PER_ADDRESS, err);
            }
            this->ChangedMemoryAddresses[alignedAddr] = {0xFF, Val};
        }

        alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
        i -= alignmentOffset;
        alignmentOffset = 0;
    }


    // Little endian

        alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
        alignedAddr = addr - alignmentOffset;
        for(uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS)
        {
            uint64_t Val = 0;
            if(size - i > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset)
            {
                for(uint32_t j = 0; j < NUM_OF_BYTES_PER_ADDRESS - alignmentOffset; j++)
                {
                    // Val <<= 8;
                    Val |= ((uint64_t)((const uint8_t*)buf)[i + j]) << (j * 8);
                }
            }
            else{
                for(uint32_t j = 0; j < size - i; j++)
                {
                    // Val <<= 8;
                    Val |= ((uint64_t)((const uint8_t*)buf)[i + j]) << (j * 8);
                }
            }
            lldb::SBError err;
            this->ChangedMemoryAddresses[alignedAddr].second &= 
            ~(((-1UL  << 8 * alignmentOffset))  >> (NUM_OF_BYTES_PER_ADDRESS - size + i - alignmentOffset) * 8);
            this->ChangedMemoryAddresses[alignedAddr].second |= (Val << 8 * alignmentOffset);


    LLVM_DEBUG(
            SS.clear();
            std::string AddrVal;
            SS << std::hex << (alignedAddr + alignmentOffset);
            SS >> AddrVal;
            if(AddrVal.size() < 2 * 8)
            {
                AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
            }
            SS.clear();
            std::string ValStr;
            SS << std::hex << Val;
            SS >> ValStr;
            uint32_t sizeToWrite = 0;
            if(size - i > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset)
            {
                if(ValStr.size() < 2 * (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset))
                {
                    ValStr = std::string(2 * (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset) - ValStr.size(), '0') + ValStr;
                }
                sizeToWrite = NUM_OF_BYTES_PER_ADDRESS - alignmentOffset;
            }
            else{
               if(ValStr.size() < 2 * (size - i))
                {
                    ValStr = std::string(2 * (size - i) - ValStr.size(), '0') + ValStr;
                }
                sizeToWrite = size - i;
            }

            llvm::dbgs() << "Writing location: " << "0x" << AddrVal << " : " << "0x" << ValStr << ", byte_size: " 
            << sizeToWrite << "\n";
        );
            alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
            i -= alignmentOffset;
            alignmentOffset = 0;
        }




    this->dump();
}

void crash_analyzer::MemoryWrapper::InvalidateAddress(uint64_t addr, size_t size)
{
    uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
    uint64_t alignedAddr = addr - alignmentOffset;
    std::stringstream SS;
    bool notLoadedYet = false;
    for(uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS)
    {
        uint8_t mask = (0xFFU >> (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset));
        if( i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset > size)
        {
            mask |= 0xFFU << (alignmentOffset + size - i);
        }
        if(this->ChangedMemoryAddresses.count(alignedAddr) == 0)
        {
            lldb::SBError err;
            uint64_t Val = 0;
            if(this->Dec)
            {
                Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(alignedAddr, NUM_OF_BYTES_PER_ADDRESS, err);
            }
            this->ChangedMemoryAddresses[alignedAddr] = {0xFF, Val};

        }
        this->ChangedMemoryAddresses[alignedAddr].first &= mask;

        alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
        i -= alignmentOffset;
        alignmentOffset = 0;
    }

    LLVM_DEBUG(
    alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
    alignedAddr = addr - alignmentOffset;
    for(uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS)
    {
        SS.clear();
        std::string AddrVal;
        SS << std::hex << (alignedAddr + alignmentOffset);
        SS >> AddrVal;
        uint32_t sizeToWrite = 0;
        if(size - i  > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset)
        {
            sizeToWrite = NUM_OF_BYTES_PER_ADDRESS - alignmentOffset;
        }
        else
        {
            sizeToWrite = size - i;
        }
        if(AddrVal.size() < 2 * 8)
        {
            AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
        }

        llvm::dbgs() << "Invalidating location: " << "0x" << AddrVal << ", byte_size: " 
        <<  sizeToWrite << "\n";
        alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
        i -= alignmentOffset;
        alignmentOffset = 0;
    }

    );


    this->dump();
}

void crash_analyzer::MemoryWrapper::dump()
{

    LLVM_DEBUG(
        std::stringstream SS;
        std::string str;

        for(auto MA = this->ChangedMemoryAddresses.begin(), ME = this->ChangedMemoryAddresses.end(); MA != ME; MA++)
        {
            for(uint32_t i = 0; i < NUM_OF_BYTES_PER_ADDRESS; i++)
            {
                SS.clear();
                std::string AddrVal;
                SS << std::hex << (MA->first + i);
                SS >> AddrVal;
                if(AddrVal.size() < 2 * 8)
                {
                    AddrVal = std::string(2 * 8 - AddrVal.size(), '0') + AddrVal;
                }
                if(MA->second.first & (1 << i))
                {
                    uint32_t Val = (uint8_t)((MA->second.second & (0xFFUL << i * 8)) >> i * 8);
                    std::string ValStr;
                    SS.clear();
                    SS << std::hex << Val;
                    SS >> ValStr;
                    if(ValStr.size() < 2 * 1)
                    {
                        ValStr = std::string(2 * 1 - ValStr.size(), '0') + ValStr;
                    }
                    llvm::dbgs() << "\tValid location: " << "0x" << AddrVal << ", byte_size: " 
                    << 1 << ", Val: " << "0x" << ValStr << "\n";
                }
                else
                {   
                    llvm::dbgs() << "\tInvalid location: " << "0x" << AddrVal << ", byte_size: " 
                    << 1 << "\n";

                }

            }
        }
    );
}
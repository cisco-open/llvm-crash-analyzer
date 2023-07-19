#include "Analysis/MemoryWrapper.h"
#include "gtest/gtest.h"

using namespace llvm;
using namespace crash_analyzer;

namespace{


TEST(MemWrapper, ReadingWritingAligned)
{
    MemoryWrapper MemWrapper;

    uint64_t ADDR = 0x00000000FF000000;
    lldb::SBError err;
    auto Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_FALSE(Val.hasValue());

    uint64_t VAL = 0xFF00000000000000;
    MemWrapper.WriteMemory(ADDR, &VAL, 8, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL);

    uint8_t VAL_BYTE = 0x01;
    MemWrapper.WriteMemory(ADDR, &VAL_BYTE, 1, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 1, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_BYTE);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8 , err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL + VAL_BYTE);

    uint16_t VAL_SHORT = 0x1000;
    MemWrapper.WriteMemory(ADDR, &VAL_SHORT, 2, err);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 2, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_SHORT);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL + VAL_SHORT);

    uint32_t VAL_INT = 0x10000000;
    MemWrapper.WriteMemory(ADDR, &VAL_INT, 4, err);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR,4, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_INT);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL + VAL_INT);

    ADDR = 0x00000000DD000000;

    MemWrapper.InvalidateAddress(ADDR, 8);

    MemWrapper.WriteMemory(ADDR, &VAL_BYTE, 1, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 1, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_BYTE);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 2, err);
    ASSERT_FALSE(Val.hasValue());

    MemWrapper.WriteMemory(ADDR, &VAL_SHORT, 2, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 2, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_SHORT);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 4, err);
    ASSERT_FALSE(Val.hasValue());

    MemWrapper.WriteMemory(ADDR, &VAL_INT, 4, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 4, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL_INT);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_FALSE(Val.hasValue());

    MemWrapper.WriteMemory(ADDR, &VAL, 8, err);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == VAL);


}

TEST(MemWrapper, InvalidatingAligned)
{
    MemoryWrapper MemWrapper;

    uint64_t ADDR = 0xFF00000000000000;
    uint64_t VAL = -1UL;
    uint8_t VAL_BYTE = 0x10;
    uint16_t VAL_SHORT = 0x1000;
    uint32_t VAL_INT = 0x10000000;
    lldb::SBError err;
    MemWrapper.WriteMemory(ADDR, &VAL_BYTE, 1, err);

    MemWrapper.InvalidateAddress(ADDR, 1);
    auto Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 1, err);
    ASSERT_FALSE(Val.hasValue());

    MemWrapper.WriteMemory(ADDR, &VAL_SHORT, 2, err);
    MemWrapper.InvalidateAddress(ADDR, 2);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 2, err);
    ASSERT_FALSE(Val.hasValue());



    MemWrapper.WriteMemory(ADDR, &VAL_INT, 4, err);
    MemWrapper.InvalidateAddress(ADDR, 4);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 4, err);
    ASSERT_FALSE(Val.hasValue());

    MemWrapper.WriteMemory(ADDR, &VAL, 8, err);
    MemWrapper.InvalidateAddress(ADDR, 8);
    Val = MemWrapper.ReadUnsignedFromMemory(ADDR, 8, err);
    ASSERT_FALSE(Val.hasValue());

}

TEST(MemWrapper, Unaligned)
{
    uint64_t ADDR = 0xFF00000000000000;
    uint64_t VAL = 0x0807060504030201;

    MemoryWrapper MemWrapper;
    lldb::SBError err;
    MemWrapper.InvalidateAddress(ADDR, 8);
    MemWrapper.InvalidateAddress(ADDR + MemoryWrapper::NUM_OF_BYTES_PER_ADDRESS, 8);
    MemWrapper.WriteMemory(ADDR + 3, &VAL, 8, err);
    auto Val = MemWrapper.ReadUnsignedFromMemory(ADDR + 3, 8, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_EQ(*Val, VAL);
    ASSERT_TRUE(*Val == VAL);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + 2, 1, err);
    ASSERT_FALSE(Val.hasValue());

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + MemoryWrapper::NUM_OF_BYTES_PER_ADDRESS + 3, 1, err);
    ASSERT_FALSE(Val.hasValue());

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + 3, 5, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == (VAL & 0x000000FFFFFFFFFF));

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + MemoryWrapper::NUM_OF_BYTES_PER_ADDRESS, 3, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_TRUE(*Val == (VAL >> 5 * 8));

    MemWrapper.InvalidateAddress(ADDR + 6, 3);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + 6, 1, err);
    ASSERT_FALSE(Val.hasValue());

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + MemoryWrapper::NUM_OF_BYTES_PER_ADDRESS, 1, err);
    ASSERT_FALSE(Val.hasValue());

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + 3, 3, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_EQ(*Val, VAL & 0x0000000000FFFFFF);

    Val = MemWrapper.ReadUnsignedFromMemory(ADDR + MemoryWrapper::NUM_OF_BYTES_PER_ADDRESS + 1, 2, err);
    ASSERT_TRUE(Val.hasValue());
    ASSERT_EQ(*Val, VAL >> 6 * 8);
}

}
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "ump_processor.h"
#include "ump_packet.h"

using namespace testing;
using namespace testing::ext;

class UmpProcessorUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

protected:
    UmpProcessor processor_;
};

// ====================================================================
// 1. Channel Voice Messages (MT = 0x2)
// ====================================================================

/**
 * @tc.name: TestChannelVoice_NoteOn
 * @tc.desc: Test Standard 3-byte Channel Message (Note On). Input: 90 3C 64
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestChannelVoice_NoteOn, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0x90, 0x3C, 0x64 };

    processor_.ProcessBytes(input, 3, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    // Word 0: 0x2 (MT) | 0x0 (Group) | 0x90 (Status) | 0x3C (Data1) | 0x64 (Data2)
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);
}

/**
 * @tc.name: TestChannelVoice_ProgramChange
 * @tc.desc: Test Standard 2-byte Channel Message (Program Change). Input: C0 05
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestChannelVoice_ProgramChange, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xC0, 0x05 };

    processor_.ProcessBytes(input, 2, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    // Word 0: 0x2 (MT) | 0x0 (Group) | 0xC0 (Status) | 0x05 (Data1) | 0x00 (Pad)
    EXPECT_EQ(results[0].Word(0), 0x20C00500U);
}

// ====================================================================
// 2. System Real-Time Messages (MT = 0x1)
// ====================================================================

/**
 * @tc.name: TestSystemRealTime_Clock
 * @tc.desc: Timing Clock (0xF8) maps to MT=0x1
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSystemRealTime_Clock, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xF8 };

    processor_.ProcessBytes(input, 1, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    // Word 0: 0x1 (MT) | 0x0 (Group) | 0xF8 (Status) | 0x00 | 0x00
    EXPECT_EQ(results[0].Word(0), 0x10F80000U);
}

// ====================================================================
// 3. System Common Messages (MT = 0x1)
// ====================================================================

/**
 * @tc.name: TestSystemCommon_SongSelect
 * @tc.desc: Song Select (0xF3) maps to MT=0x1 with 1 data byte
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSystemCommon_SongSelect, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xF3, 0x12 }; // Select Song 0x12

    processor_.ProcessBytes(input, 2, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    // Word 0: 0x1 (MT) | 0x0 (Group) | 0xF3 (Status) | 0x12 (Data1) | 0x00
    EXPECT_EQ(results[0].Word(0), 0x10F31200U);
}

/**
 * @tc.name: TestSystemCommon_TuneRequest
 * @tc.desc: Tune Request (0xF6) maps to MT=0x1
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSystemCommon_TuneRequest, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xF6 };

    processor_.ProcessBytes(input, 1, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x10F60000U);
}

// ====================================================================
// 4. System Exclusive Messages (MT = 0x3)
// ====================================================================

/**
 * @tc.name: TestSysEx_SmallComplete
 * @tc.desc: Small SysEx that fits in one UMP (MT=0x3)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSysEx_SmallComplete, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xF0, 0x01, 0x02, 0x03, 0xF7 };

    processor_.ProcessBytes(input, 5, [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    
    UmpPacket& p = results[0];
    EXPECT_EQ(p.WordCount(), 2); // SysEx UMP should be 64-bit

    // Word 0 layout: [MT:4][Grp:4][Status:4][Count:4][Data0:8][Data1:8]
    // MT=3, Status=0 (Complete), Count=3 bytes (01, 02, 03)
    EXPECT_EQ(results[0].Word(0), 0x30030102U);
    
    // Word 1 layout: [Data2:8][Data3:8][Data4:8][Data5:8]
    // Data2=03, rest are 0
    EXPECT_EQ(results[0].Word(1), 0x03000000U);
}

/**
 * @tc.name: TestSysEx_MultiPacket
 * @tc.desc: Long SysEx spanning multiple UMP packets
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSysEx_MultiPacket, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    // 9 bytes of data + F0/F7 = 11 bytes total
    uint8_t input[] = {
        0xF0,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Packet 1 payload
        0x07, 0x08,                         // Packet 2 payload
        0xF7
    };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 2);

    // --- Packet 1: Start (Status=0x1) ---
    // Count = 6 bytes (Max for SysEx7 UMP)
    // Word 0: 0x30160102 (MT=3, Stat=1, Cnt=6, D0=01, D1=02)
    // Word 1: 0x03040506
    EXPECT_EQ(results[0].Word(0), 0x30160102U);
    EXPECT_EQ(results[0].Word(1), 0x03040506U);

    // --- Packet 2: End (Status=0x3) ---
    // Count = 2 bytes (07, 08)
    // Word 0: 0x30320708 (MT=3, Stat=3, Cnt=2, D0=07, D1=08)
    // Word 1: 0x00000000
    EXPECT_EQ(results[1].Word(0), 0x30320708U);
    EXPECT_EQ(results[1].Word(1), 0x00000000U);
}

// ====================================================================
// 5. Running Status & Stream Integration (MT = 0x2)
// ====================================================================

/**
 * @tc.name: TestRunningStatus_Basic
 * @tc.desc: Test basic Running Status with Note On
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_Basic, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0x90, 0x3C, 0x64, 0x3E, 0x64 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 2);
    // Packet 1: 0x20903C64
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);
    // Packet 2: 0x20903E64 (Implicit 0x90 restored)
    EXPECT_EQ(results[1].Word(0), 0x20903E64U);
}

/**
 * @tc.name: TestRunningStatus_ProgramChange
 * @tc.desc: Test Running Status with Program Change (2-byte message)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_ProgramChange, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    uint8_t input[] = { 0xC0, 0x05, 0x06 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].Word(0), 0x20C00500U);
    EXPECT_EQ(results[1].Word(0), 0x20C00600U);
}

/**
 * @tc.name: TestRunningStatus_RealTimeInterruption
 * @tc.desc: Real-time messages should not clear running status
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_RealTimeInterruption, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    // Note On -> Clock -> Note On (Running Status)
    uint8_t input[] = { 0x90, 0x3C, 0x64, 0xF8, 0x3E, 0x64 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U); // Note On
    EXPECT_EQ(results[1].Word(0), 0x10F80000U); // Clock (MT=1)
    EXPECT_EQ(results[2].Word(0), 0x20903E64U); // Note On (Still 0x90)
}

/**
 * @tc.name: TestRunningStatus_ClearedBySysEx
 * @tc.desc: SysEx should clear running status, causing subsequent orphan data to be dropped
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_ClearedBySysEx, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    uint8_t input[] = {
        0x90, 0x3C, 0x64,                   // Note On
        0xF0, 0x7E, 0x7F, 0x06, 0x01, 0xF7, // SysEx (Identity Request)
        0x3C, 0x64                          // Orphaned data
    };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    // We expect Note On and the SysEx (Total 2 logical messages, SysEx is 1 UMP here)
    ASSERT_GE(results.size(), 2);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);
    
    // Verify that the packet after SysEx is NOT 0x20903C64
    // (which would indicate the orphan data was processed as Note On)
    for (size_t i = 1; i < results.size(); ++i) {
        EXPECT_NE(results[i].Word(0), 0x20903C64U);
    }
}

/**
 * @tc.name: TestRunningStatus_ClearedBySystemCommon
 * @tc.desc: System Common (F3) should clear running status
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_ClearedBySystemCommon, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    // Note On -> Song Select -> Attempted Running Status Note (should be dropped)
    uint8_t input[] = { 0x90, 0x3C, 0x64, 0xF3, 0x01, 0x3E, 0x64 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U); // Note On
    EXPECT_EQ(results[1].Word(0), 0x10F30100U); // Song Select (MT=1)
}

/**
 * @tc.name: TestRunningStatus_SwitchingTypes
 * @tc.desc: Test switching running status from Note On to Control Change
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_SwitchingTypes, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    uint8_t input[] = {
        0x90, 0x3C, 0x64, // Note On (3C)
        0x3E, 0x64,       // Note On (3E) - Running Status
        0xB0, 0x07, 0x7F, // CC 7 (Volume)
        0x0A, 0x40        // CC 10 (Pan) - New Running Status
    };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 4);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);
    EXPECT_EQ(results[1].Word(0), 0x20903E64U);
    EXPECT_EQ(results[2].Word(0), 0x20B0077FU);
    EXPECT_EQ(results[3].Word(0), 0x20B00A40U); // Should use 0xB0
}

/**
 * @tc.name: TestRunningStatus_Reestablishment
 * @tc.desc: Running Status cleared by F6, then re-established by 80
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRunningStatus_Reestablishment, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    uint8_t input[] = {
        0x90, 0x3C, 0x64, // Note On
        0xF6,             // System Common - Clears Running Status
        0x3E, 0x64,       // ORPHAN DATA (Should be dropped)
        0x80, 0x3C, 0x00, // Note Off (Status Re-established)
        0x3E, 0x00        // Note Off (Running Status)
    };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    // Expected: Note On, Tune Request, Note Off (1), Note Off (2)
    ASSERT_EQ(results.size(), 4);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U); // Note On
    EXPECT_EQ(results[1].Word(0), 0x10F60000U); // Tune Request
    EXPECT_EQ(results[2].Word(0), 0x20803C00U); // Note Off 1
    EXPECT_EQ(results[3].Word(0), 0x20803E00U); // Note Off 2
}

// ====================================================================
// 6. Advanced Edge Cases & Stream Robustness
// ====================================================================

/**
 * @tc.name: TestRealTime_Interruption
 * @tc.desc: Real-time message appearing inside a Channel Voice message
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRealTime_Interruption, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    // Note On (Status + Data1) -> Clock -> Note On (Data2)
    uint8_t input[] = { 0x90, 0x3C, 0xF8, 0x64 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 2);
    // Packet 1: Must be the Clock (MT=1)
    EXPECT_EQ(results[0].Word(0), 0x10F80000U);
    // Packet 2: Must be the completed Note On (MT=2)
    EXPECT_EQ(results[1].Word(0), 0x20903C64U);
}

/**
 * @tc.name: TestSysEx_Streaming
 * @tc.desc: Large SysEx processed across multiple buffer chunks
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestSysEx_Streaming, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    auto cb = [&results](const UmpPacket& p) { results.push_back(p); };

    // Call 1: Start SysEx
    uint8_t chunk1[] = { 0xF0, 0x01, 0x02 };
    processor_.ProcessBytes(chunk1, 3, cb);

    // Call 2: Fill more data (total 6 bytes reached, should trigger 1st UMP)
    uint8_t chunk2[] = { 0x03, 0x04, 0x05, 0x06 };
    processor_.ProcessBytes(chunk2, 4, cb);

    // Call 3: Finalize
    uint8_t chunk3[] = { 0x07, 0x08, 0xF7 };
    processor_.ProcessBytes(chunk3, 3, cb);

    // Expected:
    // Packet 1: Start (01 02 03 04 05 06)
    // Packet 2: End (07 08)
    ASSERT_GE(results.size(), 2);
    EXPECT_EQ((uint32_t)0x1, (results[0].Word(0) >> 20) & 0xF); // Check Status is Start (1)
}

/**
 * @tc.name: TestControl_AllNotesOff
 * @tc.desc: Test All Notes Off (CC 123)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestControl_AllNotesOff, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    uint8_t input[] = { 0xB0, 0x7B, 0x00 };
    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x20B07B00U);
}

/**
 * @tc.name: TestStream_SelfHealing
 * @tc.desc: Incomplete message should be discarded when new status arrives
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestStream_SelfHealing, TestSize.Level1)
{
    std::vector<UmpPacket> results;

    // Partial Note On (90 3C) interrupted by a fresh Note On (90 3E 64)
    uint8_t input[] = { 0x90, 0x3C, 0x90, 0x3E, 0x64 };

    processor_.ProcessBytes(input, sizeof(input), [&](const UmpPacket& p) {
        results.push_back(p);
    });

    // Should only produce ONE packet: the second Note On.
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x20903E64U);
}

// ====================================================================
// 7. Stream Fragmentation - Non-SysEx (MT = 0x2)
// ====================================================================

/**
 * @tc.name: TestStream_SplitNoteOn
 * @tc.desc: Note On split across two ProcessBytes calls
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestStream_SplitNoteOn, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    auto cb = [&results](const UmpPacket& p) { results.push_back(p); };

    uint8_t part1[] = { 0x90, 0x3C };
    processor_.ProcessBytes(part1, 2, cb);
    ASSERT_EQ(results.size(), 0); // Should not dispatch UMP for incomplete message.

    uint8_t part2[] = { 0x64 };
    processor_.ProcessBytes(part2, 1, cb);
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);
}

/**
 * @tc.name: TestStream_SplitProgramChange
 * @tc.desc: Program Change split across two ProcessBytes calls
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestStream_SplitProgramChange, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    auto cb = [&results](const UmpPacket& p) { results.push_back(p); };

    uint8_t part1[] = { 0xC0 };
    processor_.ProcessBytes(part1, 1, cb);

    uint8_t part2[] = { 0x05 };
    processor_.ProcessBytes(part2, 1, cb);

    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x20C00500U);
}

/**
 * @tc.name: TestStream_ComplexFragmentation
 * @tc.desc: Multiple messages fragmented irregularly across calls
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestStream_ComplexFragmentation, TestSize.Level1)
{
    std::vector<UmpPacket> results;
    auto cb = [&results](const UmpPacket& p) { results.push_back(p); };

    // Call 1: Partial Note On
    uint8_t chunk1[] = { 0x90, 0x3C };
    processor_.ProcessBytes(chunk1, 2, cb);
    ASSERT_EQ(results.size(), 0);

    // Call 2: Finish Note On + Start CC
    uint8_t chunk2[] = { 0x64, 0xB0 };
    processor_.ProcessBytes(chunk2, 2, cb);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].Word(0), 0x20903C64U);

    // Call 3: Finish CC
    uint8_t chunk3[] = { 0x07, 0x7F };
    processor_.ProcessBytes(chunk3, 2, cb);
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[1].Word(0), 0x20B0077FU);
}
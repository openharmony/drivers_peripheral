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

    processor_.ProcessBytes(input, 3, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, 2, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, 1, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, 2, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, 1, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, 5, [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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
    EXPECT_EQ(static_cast<uint32_t>(0x1), (results[0].Word(0) >> 20) & 0xF); // Check Status is Start (1)
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
    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

    processor_.ProcessBytes(input, sizeof(input), [&results](const UmpPacket& p) {
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

// ====================================================================
// 8. UMP -> MIDI 1.0: Channel Voice Messages Tests
// ====================================================================

/**
 * @tc.name: TestUmpToMidi1_NoteOn
 * @tc.desc: Test UMP MT=2 Note On conversion to MIDI 1.0
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_NoteOn, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20903C64U; // MT=2, Group=0, Status=0x90, Data1=0x3C, Data2=0x64

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0x90);
    EXPECT_EQ(output[1], 0x3C);
    EXPECT_EQ(output[2], 0x64);
}

/**
 * @tc.name: TestUmpToMidi1_NoteOff
 * @tc.desc: Test UMP MT=2 Note Off conversion to MIDI 1.0
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_NoteOff, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20803C00U; // MT=2, Group=0, Status=0x80, Data1=0x3C, Data2=0x00

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0x80);
    EXPECT_EQ(output[1], 0x3C);
    EXPECT_EQ(output[2], 0x00);
}

/**
 * @tc.name: TestUmpToMidi1_ProgramChange
 * @tc.desc: Test UMP MT=2 Program Change (2-byte message) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_ProgramChange, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20C00500U; // MT=2, Group=0, Status=0xC0, Data1=0x05

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], 0xC0);
    EXPECT_EQ(output[1], 0x05);
}

/**
 * @tc.name: TestUmpToMidi1_ChannelPressure
 * @tc.desc: Test UMP MT=2 Channel Pressure (2-byte message) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_ChannelPressure, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20D04000U; // MT=2, Group=0, Status=0xD0, Data1=0x40

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], 0xD0);
    EXPECT_EQ(output[1], 0x40);
}

/**
 * @tc.name: TestUmpToMidi1_PitchBend
 * @tc.desc: Test UMP MT=2 Pitch Bend (3-byte message) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_PitchBend, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20E00040U; // MT=2, Group=0, Status=0xE0, Data1=0x00, Data2=0x40

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0xE0);
    EXPECT_EQ(output[1], 0x00);
    EXPECT_EQ(output[2], 0x40);
}

/**
 * @tc.name: TestUmpToMidi1_ControlChange
 * @tc.desc: Test UMP MT=2 Control Change (3-byte message) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_ControlChange, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x20B00740U; // MT=2, Group=0, Status=0xB0, Data1=0x07, Data2=0x40

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0xB0);
    EXPECT_EQ(output[1], 0x07);
    EXPECT_EQ(output[2], 0x40);
}

// ====================================================================
// 9. UMP -> MIDI 1.0: System Common/Real-Time Messages Tests
// ====================================================================

/**
 * @tc.name: TestUmpToMidi1_TimingClock
 * @tc.desc: Test UMP MT=1 Timing Clock (1-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_TimingClock, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10F80000U; // MT=1, Group=0, Status=0xF8

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xF8);
}

/**
 * @tc.name: TestUmpToMidi1_Start
 * @tc.desc: Test UMP MT=1 Start (1-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_Start, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10FA0000U; // MT=1, Group=0, Status=0xFA

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xFA);
}

/**
 * @tc.name: TestUmpToMidi1_Stop
 * @tc.desc: Test UMP MT=1 Stop (1-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_Stop, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10FC0000U; // MT=1, Group=0, Status=0xFC

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xFC);
}

/**
 * @tc.name: TestUmpToMidi1_SongPositionPointer
 * @tc.desc: Test UMP MT=1 Song Position Pointer (3-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SongPositionPointer, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10F21234U; // MT=1, Group=0, Status=0xF2, Data1=0x12, Data2=0x34

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0xF2);
    EXPECT_EQ(output[1], 0x12);
    EXPECT_EQ(output[2], 0x34);
}

/**
 * @tc.name: TestUmpToMidi1_SongSelect
 * @tc.desc: Test UMP MT=1 Song Select (2-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SongSelect, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10F30500U; // MT=1, Group=0, Status=0xF3, Data1=0x05

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], 0xF3);
    EXPECT_EQ(output[1], 0x05);
}

/**
 * @tc.name: TestUmpToMidi1_TuneRequest
 * @tc.desc: Test UMP MT=1 Tune Request (1-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_TuneRequest, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10F60000U; // MT=1, Group=0, Status=0xF6

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xF6);
}

// ====================================================================
// 10. UMP -> MIDI 1.0: SysEx Messages Tests (Core)
// ====================================================================

/**
 * @tc.name: TestUmpToMidi1_SysEx_Complete
 * @tc.desc: Test complete single-packet SysEx conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_Complete, TestSize.Level1)
{
    std::vector<uint8_t> output;
    // MT=3, Group=0, Status=0 (Complete), Count=3, Data=[01,02,03]
    uint32_t ump[] = { 0x30030102U, 0x03000000U };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Expected: F0 01 02 03 F7
    ASSERT_EQ(output.size(), 5);
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[1], 0x01);
    EXPECT_EQ(output[2], 0x02);
    EXPECT_EQ(output[3], 0x03);
    EXPECT_EQ(output[4], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_Complete_6Bytes
 * @tc.desc: Test complete single-packet SysEx with 6 bytes of data
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_Complete_6Bytes, TestSize.Level1)
{
    std::vector<uint8_t> output;
    // MT=3, Group=0, Status=0 (Complete), Count=6, Data=[01,02,03,04,05,06]
    uint32_t ump[] = { 0x30060102U, 0x03040506U };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Expected: F0 01 02 03 04 05 06 F7
    ASSERT_EQ(output.size(), 8);
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[1], 0x01);
    EXPECT_EQ(output[2], 0x02);
    EXPECT_EQ(output[3], 0x03);
    EXPECT_EQ(output[4], 0x04);
    EXPECT_EQ(output[5], 0x05);
    EXPECT_EQ(output[6], 0x06);
    EXPECT_EQ(output[7], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_EmptyComplete
 * @tc.desc: Test empty complete SysEx (only F0 and F7)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_EmptyComplete, TestSize.Level1)
{
    std::vector<uint8_t> output;
    // MT=3, Group=0, Status=0 (Complete), Count=0
    uint32_t ump[] = { 0x30000000U, 0x00000000U };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Expected: F0 F7
    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[1], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_StartEnd
 * @tc.desc: Test multi-packet SysEx with Start+End (2 packets)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_StartEnd, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Packet 1: Start, Status=1, Count=6, Data=[01,02,03,04,05,06]
    uint32_t ump1[] = { 0x30160102U, 0x03040506U };
    // Packet 2: End, Status=3, Count=2, Data=[07,08]
    uint32_t ump2[] = { 0x30320708U, 0x00000000U };

    auto cb = [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    };

    processor_.ProcessUmp(ump1, 2, cb);
    processor_.ProcessUmp(ump2, 2, cb);

    // Expected: F0 01 02 03 04 05 06 07 08 F7
    ASSERT_EQ(output.size(), 10);
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[1], 0x01);
    EXPECT_EQ(output[2], 0x02);
    EXPECT_EQ(output[3], 0x03);
    EXPECT_EQ(output[4], 0x04);
    EXPECT_EQ(output[5], 0x05);
    EXPECT_EQ(output[6], 0x06);
    EXPECT_EQ(output[7], 0x07);
    EXPECT_EQ(output[8], 0x08);
    EXPECT_EQ(output[9], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_StartContinueEnd
 * @tc.desc: Test multi-packet SysEx with Start+Continue+End (3 packets)
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_StartContinueEnd, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Packet 1: Start, Status=1, Count=6, Data=[01,02,03,04,05,06]
    uint32_t ump1[] = { 0x30160102U, 0x03040506U };
    // Packet 2: Continue, Status=2, Count=6, Data=[07,08,09,0A,0B,0C]
    uint32_t ump2[] = { 0x30260708U, 0x090A0B0CU };
    // Packet 3: End, Status=3, Count=2, Data=[0D,0E]
    uint32_t ump3[] = { 0x30320D0EU, 0x00000000U };

    auto cb = [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    };

    processor_.ProcessUmp(ump1, 2, cb);
    processor_.ProcessUmp(ump2, 2, cb);
    processor_.ProcessUmp(ump3, 2, cb);

    // Expected: F0 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E F7
    ASSERT_EQ(output.size(), 16);
    EXPECT_EQ(output[0], 0xF0);
    for (int i = 1; i <= 14; ++i) {
        EXPECT_EQ(output[i], static_cast<uint8_t>(i));
    }
    EXPECT_EQ(output[15], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_LargeMultiPacket
 * @tc.desc: Test large multi-packet SysEx spanning many packets
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_LargeMultiPacket, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // 4 packets: Start + Continue + Continue + End
    // Packet 1: Start, Count=6
    uint32_t ump1[] = { 0x30160102U, 0x03040506U };
    // Packet 2: Continue, Count=6
    uint32_t ump2[] = { 0x30260708U, 0x090A0B0CU };
    // Packet 3: Continue, Count=6
    uint32_t ump3[] = { 0x30260D0EU, 0x0F101112U };
    // Packet 4: End, Count=2
    uint32_t ump4[] = { 0x30321314U, 0x00000000U };

    auto cb = [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    };

    processor_.ProcessUmp(ump1, 2, cb);
    processor_.ProcessUmp(ump2, 2, cb);
    processor_.ProcessUmp(ump3, 2, cb);
    processor_.ProcessUmp(ump4, 2, cb);

    // Expected: F0 + 20 data bytes + F7 = 22 bytes total
    ASSERT_EQ(output.size(), 22);
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[21], 0xF7);
}

// ====================================================================
// 11. UMP -> MIDI 1.0: Boundary Conditions Tests
// ====================================================================

/**
 * @tc.name: TestUmpToMidi1_MultipleMessageTypes
 * @tc.desc: Test processing multiple message types in sequence
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_MultipleMessageTypes, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Note On (MT=2), Clock (MT=1), SysEx Complete (MT=3)
    uint32_t ump[] = {
        0x20903C64U,              // Note On
        0x10F80000U,              // Clock
        0x30030102U, 0x03000000U  // SysEx Complete
    };

    processor_.ProcessUmp(ump, 4, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Expected: 90 3C 64 F8 F0 01 02 03 F7
    ASSERT_EQ(output.size(), 9);
    // Note On
    EXPECT_EQ(output[0], 0x90);
    EXPECT_EQ(output[1], 0x3C);
    EXPECT_EQ(output[2], 0x64);
    // Clock
    EXPECT_EQ(output[3], 0xF8);
    // SysEx
    EXPECT_EQ(output[4], 0xF0);
    EXPECT_EQ(output[5], 0x01);
    EXPECT_EQ(output[6], 0x02);
    EXPECT_EQ(output[7], 0x03);
    EXPECT_EQ(output[8], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysExInterrupted
 * @tc.desc: Test SysEx interrupted by a new Start packet
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysExInterrupted, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Packet 1: Start, Count=6, Data=01 02 03 04 05 06
    uint32_t ump1[] = { 0x30160102U, 0x03040506U };
    // Packet 2: Another Start (interrupts previous SysEx), Count=2, Data=AA AB
    uint32_t ump2[] = { 0x3012AAABU, 0x00000000U };
    // Packet 3: End, Count=2, Data=AC AD
    uint32_t ump3[] = { 0x3032ACADU, 0x00000000U };

    auto cb = [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    };

    processor_.ProcessUmp(ump1, 2, cb);
    processor_.ProcessUmp(ump2, 2, cb);
    processor_.ProcessUmp(ump3, 2, cb);

    // First Start: F0 01 02 03 04 05 06 = 7 bytes (no F7, interrupted)
    // Second Start: F0 AA AB = 3 bytes
    // End: AC AD F7 = 3 bytes
    // Total: 7 + 3 + 3 = 13 bytes
    ASSERT_EQ(output.size(), 13);
    // First packet data
    EXPECT_EQ(output[0], 0xF0);
    EXPECT_EQ(output[1], 0x01);
    // Second Start data
    EXPECT_EQ(output[7], 0xF0);
    EXPECT_EQ(output[8], 0xAA);
    EXPECT_EQ(output[9], 0xAB);
    // End data
    EXPECT_EQ(output[10], 0xAC);
    EXPECT_EQ(output[11], 0xAD);
    EXPECT_EQ(output[12], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_UnknownMessageType
 * @tc.desc: Test that unknown message types are skipped
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_UnknownMessageType, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Unknown MT=0x4, followed by valid Note On
    uint32_t ump[] = {
        0x40000000U,    // Unknown MT
        0x20903C64U     // Note On
    };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Only Note On should be converted
    ASSERT_EQ(output.size(), 3);
    EXPECT_EQ(output[0], 0x90);
    EXPECT_EQ(output[1], 0x3C);
    EXPECT_EQ(output[2], 0x64);
}

/**
 * @tc.name: TestUmpToMidi1_ResetClearsSysEx
 * @tc.desc: Test that Reset() clears SysEx state
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_ResetClearsSysEx, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Start a SysEx
    uint32_t ump1[] = { 0x30160102U, 0x03040506U };
    processor_.ProcessUmp(ump1, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Reset
    processor_.Reset();

    // Continue after reset should produce nothing (state was cleared)
    output.clear();
    uint32_t ump2[] = { 0x30220708U, 0x00000000U };
    processor_.ProcessUmp(ump2, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Continue without active SysEx should produce nothing
    ASSERT_EQ(output.size(), 0);
}

/**
 * @tc.name: TestUmpToMidi1_EmptyInput
 * @tc.desc: Test empty input handling
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_EmptyInput, TestSize.Level1)
{
    std::vector<uint8_t> output;

    processor_.ProcessUmp(nullptr, 0, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 0);

    // Also test with valid pointer but zero count
    uint32_t dummy = 0;
    processor_.ProcessUmp(&dummy, 0, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 0);
}

// ====================================================================
// 12. UMP -> MIDI 1.0: Round-Trip Consistency Tests
// ====================================================================

/**
 * @tc.name: TestRoundTrip_ChannelVoice
 * @tc.desc: Test MIDI 1.0 -> UMP -> MIDI 1.0 round trip for Channel Voice
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRoundTrip_ChannelVoice, TestSize.Level1)
{
    // Original MIDI 1.0 data
    uint8_t original[] = { 0x90, 0x3C, 0x64 };

    // Step 1: MIDI 1.0 -> UMP
    std::vector<UmpPacket> umpResults;
    processor_.ProcessBytes(original, 3, [&umpResults](const UmpPacket& p) {
        umpResults.push_back(p);
    });
    ASSERT_EQ(umpResults.size(), 1);

    // Step 2: UMP -> MIDI 1.0
    std::vector<uint8_t> midi1Results;
    processor_.ProcessUmpPacket(umpResults[0], [&midi1Results](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            midi1Results.push_back(data[i]);
        }
    });

    // Verify round trip
    ASSERT_EQ(midi1Results.size(), 3);
    EXPECT_EQ(midi1Results[0], original[0]);
    EXPECT_EQ(midi1Results[1], original[1]);
    EXPECT_EQ(midi1Results[2], original[2]);
}

/**
 * @tc.name: TestRoundTrip_SysEx_Complete
 * @tc.desc: Test MIDI 1.0 -> UMP -> MIDI 1.0 round trip for SysEx
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRoundTrip_SysEx_Complete, TestSize.Level1)
{
    // Original MIDI 1.0 SysEx
    uint8_t original[] = { 0xF0, 0x01, 0x02, 0x03, 0xF7 };

    // Reset to clear any previous state
    processor_.Reset();

    // Step 1: MIDI 1.0 -> UMP
    std::vector<UmpPacket> umpResults;
    processor_.ProcessBytes(original, 5, [&umpResults](const UmpPacket& p) {
        umpResults.push_back(p);
    });
    ASSERT_EQ(umpResults.size(), 1);

    // Step 2: UMP -> MIDI 1.0
    processor_.Reset();
    std::vector<uint8_t> midi1Results;
    processor_.ProcessUmpPacket(umpResults[0], [&midi1Results](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            midi1Results.push_back(data[i]);
        }
    });

    // Verify round trip
    ASSERT_EQ(midi1Results.size(), 5);
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(midi1Results[i], original[i]) << "Mismatch at index " << i;
    }
}

// ====================================================================
// 13. UMP -> MIDI 1.0: Additional Edge Case Tests
// ====================================================================

/**
 * @tc.name: TestUmpToMidi1_SysEx_ContinueWithoutStart
 * @tc.desc: Test Continue packet received without prior Start
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_ContinueWithoutStart, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // Continue packet without any prior Start
    uint32_t ump[] = { 0x30260102U, 0x03040506U };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Should produce no output (Continue is ignored when not in active SysEx)
    ASSERT_EQ(output.size(), 0);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_EndWithoutStart
 * @tc.desc: Test End packet received without prior Start
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_EndWithoutStart, TestSize.Level1)
{
    std::vector<uint8_t> output;

    // End packet without any prior Start
    uint32_t ump[] = { 0x30320102U, 0x00000000U };

    processor_.ProcessUmp(ump, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // End should still produce output (data + F7) even without Start
    // This handles malformed streams gracefully
    ASSERT_EQ(output.size(), 3); // 01 02 F7
    EXPECT_EQ(output[0], 0x01);
    EXPECT_EQ(output[1], 0x02);
    EXPECT_EQ(output[2], 0xF7);
}

/**
 * @tc.name: TestUmpToMidi1_SysEx_CountBoundary
 * @tc.desc: Test SysEx with count=0 for each status type
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_SysEx_CountBoundary, TestSize.Level1)
{
    // Test count=0 with Start then End
    std::vector<uint8_t> output;

    // Start with count=0
    uint32_t ump1[] = { 0x30100000U, 0x00000000U };
    processor_.ProcessUmp(ump1, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Should output F0 only
    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xF0);

    // End with count=0
    output.clear();
    uint32_t ump2[] = { 0x30300000U, 0x00000000U };
    processor_.ProcessUmp(ump2, 2, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    // Should output F7 only
    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], 0xF7);
}

/**
 * @tc.name: TestRoundTrip_SysEx_MultiPacket
 * @tc.desc: Test MIDI 1.0 -> UMP -> MIDI 1.0 round trip for multi-packet SysEx
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestRoundTrip_SysEx_MultiPacket, TestSize.Level1)
{
    // Original MIDI 1.0 SysEx (9 data bytes)
    uint8_t original[] = {
        0xF0,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
        0xF7
    };

    processor_.Reset();

    // Step 1: MIDI 1.0 -> UMP
    std::vector<UmpPacket> umpResults;
    processor_.ProcessBytes(original, sizeof(original), [&umpResults](const UmpPacket& p) {
        umpResults.push_back(p);
    });
    ASSERT_EQ(umpResults.size(), 2);

    // Step 2: UMP -> MIDI 1.0
    processor_.Reset();
    std::vector<uint8_t> midi1Results;
    for (const auto& p : umpResults) {
        processor_.ProcessUmpPacket(p, [&midi1Results](const uint8_t* data, size_t len) {
            for (size_t i = 0; i < len; ++i) {
                midi1Results.push_back(data[i]);
            }
        });
    }

    // Verify round trip
    ASSERT_EQ(midi1Results.size(), sizeof(original));
    for (size_t i = 0; i < sizeof(original); ++i) {
        EXPECT_EQ(midi1Results[i], original[i]) << "Mismatch at index " << i;
    }
}

/**
 * @tc.name: TestUmpToMidi1_MTCQuarterFrame
 * @tc.desc: Test UMP MT=1 MTC Quarter Frame (2-byte) conversion
 * @tc.type: FUNC
 */
HWTEST_F(UmpProcessorUnitTest, TestUmpToMidi1_MTCQuarterFrame, TestSize.Level1)
{
    std::vector<uint8_t> output;
    uint32_t ump = 0x10F11200U; // MT=1, Group=0, Status=0xF1, Data1=0x12

    processor_.ProcessUmp(&ump, 1, [&output](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            output.push_back(data[i]);
        }
    });

    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], 0xF1);
    EXPECT_EQ(output[1], 0x12);
}
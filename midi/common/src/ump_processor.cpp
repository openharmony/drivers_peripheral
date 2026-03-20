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

#include "ump_processor.h"
#include <vector>
namespace {
    // --- MIDI 1.0 Constants ---
    constexpr uint8_t MIDI_REALTIME_START = 0xF8;
    constexpr uint8_t MIDI_STATUS_START = 0x80;
    constexpr uint8_t MIDI_SYSEX_START = 0xF0;
    constexpr uint8_t MIDI_SYSEX_END = 0xF7;
    constexpr uint8_t MIDI_SYSTEM_COMMON_END = 0xF0;
    constexpr uint8_t MIDI_STATUS_PROG_CHANGE = 0xC0;
    constexpr uint8_t MIDI_STATUS_CHAN_PRESSURE = 0xD0;
    constexpr uint8_t MIDI_COMMON_MTC_QUARTER = 0xF1;
    constexpr uint8_t MIDI_COMMON_SONG_POS = 0xF2;
    constexpr uint8_t MIDI_COMMON_SONG_SEL = 0xF3;
    
    // --- UMP Constants ---
    constexpr uint8_t UMP_MT_SYSTEM = 0x1;
    constexpr uint8_t UMP_MT_CHANNEL = 0x2;
    constexpr uint8_t UMP_MT_DATA = 0x3;
    
    constexpr uint8_t SYSEX_STATUS_COMPLETE = 0x0;
    constexpr uint8_t SYSEX_STATUS_START = 0x1;
    constexpr uint8_t SYSEX_STATUS_CONTINUE = 0x2;
    constexpr uint8_t SYSEX_STATUS_END = 0x3;

    constexpr uint8_t MAX_GROUP_ID = 0x0F;
    // --- Bit Shifts ---
    constexpr uint32_t SHIFT_MT = 28;
    constexpr uint32_t SHIFT_GROUP = 24;
    constexpr uint32_t SHIFT_STATUS = 20; // For SysEx Status (MT=3)
    constexpr uint32_t SHIFT_COUNT = 16;  // For SysEx Count
    constexpr uint32_t SHIFT_BYTE_0 = 16; // For MT=1/2 Status
    constexpr uint32_t SHIFT_BYTE_1 = 8;
    constexpr uint32_t SHIFT_BYTE_2 = 0;
    constexpr uint32_t SHIFT_BYTE_3 = 24; // In Word 1
    constexpr uint32_t SHIFT_BYTE_4 = 16; // In Word 1
    constexpr uint32_t SHIFT_BYTE_5 = 8;  // In Word 1
    constexpr uint32_t SHIFT_BYTE_6 = 0;  // In Word 1

    // --- Buffer Index Constants (Fix for 2, 3, 4, 5 magic numbers) ---
    constexpr uint8_t INDEX_0 = 0;
    constexpr uint8_t INDEX_1 = 1;
    constexpr uint8_t INDEX_2 = 2;
    constexpr uint8_t INDEX_3 = 3;
    constexpr uint8_t INDEX_4 = 4;
    constexpr uint8_t INDEX_5 = 5;

    constexpr int DATA_LEN_2 = 2;

    // --- UMP Packet Word Constants ---
    constexpr uint8_t UMP_WORD_COUNT_MT3 = 2;            // MT=3 packets use 2 words
    constexpr uint8_t UMP_PACKET_MAX_WORDS = 4;          // Maximum words in an UmpPacket
    constexpr uint8_t SYSEX_DATA_BYTES_PER_PACKET = 6;   // Max SysEx data bytes per UMP packet
}

UmpProcessor::UmpProcessor()
    : group_(0),
      cv_pos_(0), running_status_(0), expected_len_(0),
      in_sysex_(false), sysex_pos_(0), sysex_has_started_(false),
      reverse_sysex_active_(false)
{
    // Initialize buffers to zero
    for (auto &b : cv_buffer_) {
        b = 0;
    }
    for (auto &b : sysex_buffer_) {
        b = 0;
    }
}

void UmpProcessor::SetGroup(uint8_t group)
{
    if (group <= MAX_GROUP_ID) group_ = group;
}

bool UmpProcessor::HandleRealTime(uint8_t byte, UmpCallback callback)
{
    if (byte < MIDI_REALTIME_START) {
        return false;
    }
    // 1. Handle Real-Time Messages (MT=1) - Priority High
    // These can interrupt anything, including SysEx, without changing state.
    uint32_t mt1 = (static_cast<uint32_t>(UMP_MT_SYSTEM) << SHIFT_MT) |
                   (static_cast<uint32_t>(group_) << SHIFT_GROUP) |
                   (static_cast<uint32_t>(byte) << SHIFT_BYTE_0);
    callback({ mt1 });
    return true;
}

void UmpProcessor::HandleStatusByte(uint8_t byte, UmpCallback callback)
{
    cv_pos_ = 0; // New status interrupts accumulation

    if (byte == MIDI_SYSEX_START) {
        in_sysex_ = true;
        sysex_pos_ = 0;
        sysex_has_started_ = false;
        running_status_ = 0;
        return;
    }

    if (byte == MIDI_SYSEX_END) {
        if (in_sysex_) {
            FinalizeSysEx(callback);
            in_sysex_ = false;
        }
        running_status_ = 0;
        return;
    }

    // Normal Channel Voice or System Common
    in_sysex_ = false;
    cv_buffer_[0] = byte;
    cv_pos_ = 1;
    expected_len_ = static_cast<uint8_t>(GetExpectedDataLength(byte));

    if (byte < MIDI_SYSTEM_COMMON_END) {
        running_status_ = byte;
    } else {
        running_status_ = 0;
    }

    if (expected_len_ == 0) {
        DispatchChannelMessage(callback);
        cv_pos_ = 0;
    }
}

void UmpProcessor::HandleChannelData(uint8_t byte, UmpCallback callback)
{
    // Recover Running Status
    if (cv_pos_ == 0 && running_status_ != 0) {
        cv_buffer_[0] = running_status_;
        cv_buffer_[1] = byte;
        cv_pos_ = INDEX_2;
        expected_len_ = static_cast<uint8_t>(GetExpectedDataLength(running_status_));
    } else if (cv_pos_ > 0 && cv_pos_ < CV_BUFFER_SIZE) {
        cv_buffer_[cv_pos_++] = byte;
    } else {
        return; // Orphaned byte
    }

    if (cv_pos_ == (expected_len_ + 1)) {
        DispatchChannelMessage(callback);
        cv_pos_ = 0;
    }
}

void UmpProcessor::HandleDataByte(uint8_t byte, UmpCallback callback)
{
    if (in_sysex_) {
        ProcessSysExData(byte, callback);
    } else {
        HandleChannelData(byte, callback);
    }
}

void UmpProcessor::ProcessBytes(const uint8_t* data, size_t len,
    UmpCallback callback)
{
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];

        if (HandleRealTime(b, callback)) {
            continue;
        }

        if (b >= MIDI_STATUS_START) {
            HandleStatusByte(b, callback);
        } else {
            HandleDataByte(b, callback);
        }
    }
}

int UmpProcessor::GetExpectedDataLength(uint8_t status)
{
    // Fix G.CNS.02: Use constants
    if (status < MIDI_SYSTEM_COMMON_END) {
        uint8_t type = status & 0xF0;
        if (type == MIDI_STATUS_PROG_CHANGE || type == MIDI_STATUS_CHAN_PRESSURE) return 1;
        return DATA_LEN_2;
    }

    switch (status) {
        case MIDI_COMMON_MTC_QUARTER:
        case MIDI_COMMON_SONG_SEL:
            return 1;
        case MIDI_COMMON_SONG_POS:
            return DATA_LEN_2;
        default:
            return 0;
    }
}

void UmpProcessor::DispatchChannelMessage(UmpCallback callback)
{
    uint8_t status = cv_buffer_[0];
    uint32_t mt = (status < MIDI_SYSTEM_COMMON_END) ? UMP_MT_CHANNEL : UMP_MT_SYSTEM;
    
    uint32_t w0 = (mt << SHIFT_MT) | (static_cast<uint32_t>(group_) << SHIFT_GROUP) |
                  (static_cast<uint32_t>(status) << SHIFT_BYTE_0);

    if (expected_len_ >= 1) w0 |= (static_cast<uint32_t>(cv_buffer_[1]) << SHIFT_BYTE_1);
    if (expected_len_ == INDEX_2) w0 |= (static_cast<uint32_t>(cv_buffer_[INDEX_2]) << SHIFT_BYTE_2);

    callback({ w0 });
}

// --- SysEx Logic (MT=3) ---
void UmpProcessor::ProcessSysExData(uint8_t byte, UmpCallback callback)
{
    if (sysex_pos_ < SYSEX_BUFFER_SIZE) {
        sysex_buffer_[sysex_pos_++] = byte;
    }

    if (sysex_pos_ == SYSEX_BUFFER_SIZE) {
        uint8_t status = sysex_has_started_ ? SYSEX_STATUS_CONTINUE : SYSEX_STATUS_START;
        DispatchSysExPacket(callback, status, static_cast<uint8_t>(SYSEX_BUFFER_SIZE));
        sysex_pos_ = 0;
        sysex_has_started_ = true;
    }
}

void UmpProcessor::FinalizeSysEx(UmpCallback callback)
{
    uint8_t status = sysex_has_started_ ? SYSEX_STATUS_END : SYSEX_STATUS_COMPLETE;
    DispatchSysExPacket(callback, status, sysex_pos_);
    sysex_pos_ = 0;
    sysex_has_started_ = false;
}

void UmpProcessor::DispatchSysExPacket(UmpCallback callback, uint8_t status_code, uint8_t byte_count)
{
    /**
     * UMP MIDI 1.0 System Exclusive (MT=3):
     * Word 0: [MT(4bit:3)] [Group(4bit)] [Status(4bit)] [Count(4bit)] [Data1(8bit)] [Data2(8bit)]
     * Word 1: [Data3(8bit)] [Data4(8bit)] [Data5(8bit)] [Data6(8bit)]
     */

    uint32_t w0 = (static_cast<uint32_t>(UMP_MT_DATA) << SHIFT_MT) |
                  (static_cast<uint32_t>(group_) << SHIFT_GROUP) |
                  (static_cast<uint32_t>(status_code) << SHIFT_STATUS) |
                  (static_cast<uint32_t>(byte_count) << SHIFT_COUNT);
    
    if (byte_count > INDEX_0) {
        w0 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_0]) << SHIFT_BYTE_1);
    }
    if (byte_count > INDEX_1) {
        w0 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_1]) << SHIFT_BYTE_2);
    }
    uint32_t w1 = 0;
    if (byte_count > INDEX_2) {
        w1 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_2]) << SHIFT_BYTE_3);
    }
    if (byte_count > INDEX_3) {
        w1 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_3]) << SHIFT_BYTE_4);
    }
    if (byte_count > INDEX_4) {
        w1 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_4]) << SHIFT_BYTE_5);
    }
    if (byte_count > INDEX_5) {
        w1 |= (static_cast<uint32_t>(sysex_buffer_[INDEX_5]) << SHIFT_BYTE_6);
    }

    callback({ w0, w1 });
}

// ============================================================
// Part 4: UMP -> MIDI 1.0 (New Implementation)
// ============================================================

void UmpProcessor::Reset()
{
    // Clear MIDI 1.0 -> UMP state
    cv_pos_ = 0;
    running_status_ = 0;
    expected_len_ = 0;
    in_sysex_ = false;
    sysex_pos_ = 0;
    sysex_has_started_ = false;

    for (auto &b : cv_buffer_) {
        b = 0;
    }
    for (auto &b : sysex_buffer_) {
        b = 0;
    }

    // Clear UMP -> MIDI 1.0 state
    reverse_sysex_active_ = false;
}

void UmpProcessor::ProcessUmp(const uint32_t* packets, size_t wordCount, Midi1Callback callback)
{
    if (packets == nullptr || wordCount == 0) {
        return;
    }

    for (size_t i = 0; i < wordCount;) {
        uint32_t word0 = packets[i];
        uint8_t mt = (word0 >> SHIFT_MT) & 0x0F;

        switch (mt) {
            case UMP_MT_SYSTEM: // MT=0x1
                ProcessUmpType1(word0, callback);
                i += 1;
                break;
            case UMP_MT_CHANNEL: // MT=0x2
                ProcessUmpType2(word0, callback);
                i += 1;
                break;
            case UMP_MT_DATA: // MT=0x3
                if (i + 1 < wordCount) {
                    ProcessUmpType3(word0, packets[i + 1], callback);
                    i += UMP_WORD_COUNT_MT3;
                } else {
                    // Incomplete MT=3 packet (missing word1), skip with zero word1
                    ProcessUmpType3(word0, 0, callback);
                    i += 1;
                }
                break;
            default:
                // Unknown message type, skip one word
                i += 1;
                break;
        }
    }
}

void UmpProcessor::ProcessUmpPacket(const UmpPacket& packet, Midi1Callback callback)
{
    uint8_t wordCount = packet.WordCount();
    if (wordCount == 0) {
        return;
    }

    // Extract words from UmpPacket
    uint32_t words[UMP_PACKET_MAX_WORDS] = {0};
    for (uint8_t i = 0; i < wordCount && i < UMP_PACKET_MAX_WORDS; ++i) {
        words[i] = packet.Word(i);
    }

    ProcessUmp(words, wordCount, callback);
}

void UmpProcessor::ProcessUmpType1(uint32_t word0, Midi1Callback callback)
{
    /**
     * MT=0x1: System Common / Real-Time Messages (32-bit)
     * Word 0 Layout:
     * [MT:4][Group:4][Status:8][Data1:8][Data2:8]
     *  28     24-27    16-23     8-15     0-7
     */
    uint8_t status = (word0 >> SHIFT_BYTE_0) & 0xFF;
    uint8_t data1 = (word0 >> SHIFT_BYTE_1) & 0xFF;
    uint8_t data2 = (word0 >> SHIFT_BYTE_2) & 0xFF;

    std::vector<uint8_t> output;

    switch (status) {
        case 0xF1: // MTC Quarter Frame - 2 bytes
            output.push_back(status);
            output.push_back(data1);
            break;
        case 0xF2: // Song Position Pointer - 3 bytes
            output.push_back(status);
            output.push_back(data1);
            output.push_back(data2);
            break;
        case 0xF3: // Song Select - 2 bytes
            output.push_back(status);
            output.push_back(data1);
            break;
        case 0xF6: // Tune Request - 1 byte
            output.push_back(status);
            break;
        case 0xF8: // Timing Clock - 1 byte
        case 0xF9: // Measure End (Undefined/MSB)
        case 0xFA: // Start - 1 byte
        case 0xFB: // Continue - 1 byte
        case 0xFC: // Stop - 1 byte
        case 0xFD: // Undefined
        case 0xFE: // Active Sensing - 1 byte
        case 0xFF: // System Reset - 1 byte
            output.push_back(status);
            break;
        default:
            // Unknown system message, ignore
            break;
    }

    if (!output.empty()) {
        callback(output.data(), output.size());
    }
}

void UmpProcessor::ProcessUmpType2(uint32_t word0, Midi1Callback callback)
{
    /**
     * MT=0x2: Channel Voice Messages (32-bit)
     * Word 0 Layout:
     * [MT:4][Group:4][Status:8][Data1:8][Data2:8]
     *  28     24-27    16-23     8-15     0-7
     */
    uint8_t status = (word0 >> SHIFT_BYTE_0) & 0xFF;
    uint8_t data1 = (word0 >> SHIFT_BYTE_1) & 0xFF;
    uint8_t data2 = (word0 >> SHIFT_BYTE_2) & 0xFF;

    std::vector<uint8_t> output;
    output.push_back(status);

    uint8_t cmd = status & 0xF0;

    if (cmd == MIDI_STATUS_PROG_CHANGE || cmd == MIDI_STATUS_CHAN_PRESSURE) {
        // 2-byte messages (status + 1 data byte)
        output.push_back(data1);
    } else {
        // 3-byte messages (status + 2 data bytes)
        output.push_back(data1);
        output.push_back(data2);
    }

    callback(output.data(), output.size());
}

void UmpProcessor::ProcessUmpType3(uint32_t word0, uint32_t word1, Midi1Callback callback)
{
    /**
     * MT=0x3: SysEx Data Messages (64-bit)
     * Word 0 Layout:
     * [MT:4][Group:4][Status:4][Count:4][Data1:8][Data2:8]
     *  28     24-27    20-23    16-19    8-15     0-7
     *
     * Word 1 Layout:
     * [Data3:8][Data4:8][Data5:8][Data6:8]
     *   24-31    16-23     8-15     0-7
     */
    uint8_t status = (word0 >> SHIFT_STATUS) & 0x0F;
    uint8_t count = (word0 >> SHIFT_COUNT) & 0x0F;

    // Extract 6 bytes of data
    uint8_t data[SYSEX_DATA_BYTES_PER_PACKET];
    data[INDEX_0] = (word0 >> SHIFT_BYTE_1) & 0xFF;
    data[INDEX_1] = (word0 >> SHIFT_BYTE_2) & 0xFF;
    data[INDEX_2] = (word1 >> SHIFT_BYTE_3) & 0xFF;
    data[INDEX_3] = (word1 >> SHIFT_BYTE_4) & 0xFF;
    data[INDEX_4] = (word1 >> SHIFT_BYTE_5) & 0xFF;
    data[INDEX_5] = (word1 >> SHIFT_BYTE_6) & 0xFF;

    std::vector<uint8_t> output;

    switch (status) {
        case SYSEX_STATUS_COMPLETE: // 0x0
            // Complete single-packet SysEx: F0 + data[0..count-1] + F7
            output.push_back(MIDI_SYSEX_START);
            for (uint8_t i = 0; i < count && i < SYSEX_DATA_BYTES_PER_PACKET; ++i) {
                output.push_back(data[i]);
            }
            output.push_back(MIDI_SYSEX_END);
            reverse_sysex_active_ = false;
            break;

        case SYSEX_STATUS_START: // 0x1
            // Multi-packet start: F0 + data[0..count-1]
            output.push_back(MIDI_SYSEX_START);
            for (uint8_t i = 0; i < count && i < SYSEX_DATA_BYTES_PER_PACKET; ++i) {
                output.push_back(data[i]);
            }
            reverse_sysex_active_ = true;
            break;

        case SYSEX_STATUS_CONTINUE: // 0x2
            // Multi-packet continue: output data[0..count-1]
            if (reverse_sysex_active_) {
                for (uint8_t i = 0; i < count && i < SYSEX_DATA_BYTES_PER_PACKET; ++i) {
                    output.push_back(data[i]);
                }
            }
            break;

        case SYSEX_STATUS_END: // 0x3
            // Multi-packet end: data[0..count-1] + F7
            for (uint8_t i = 0; i < count && i < SYSEX_DATA_BYTES_PER_PACKET; ++i) {
                output.push_back(data[i]);
            }
            output.push_back(MIDI_SYSEX_END);
            reverse_sysex_active_ = false;
            break;

        default:
            // Unknown status, reset state
            reverse_sysex_active_ = false;
            break;
    }

    if (!output.empty()) {
        callback(output.data(), output.size());
    }
}
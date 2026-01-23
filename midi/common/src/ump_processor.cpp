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
}

UmpProcessor::UmpProcessor()
    : group_(0),
      cv_pos_(0), running_status_(0), expected_len_(0),
      in_sysex_(false), sysex_pos_(0), sysex_has_started_(false)
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
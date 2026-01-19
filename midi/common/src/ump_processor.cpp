/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
    if (group <= 0x0F) group_ = group;
}

void UmpProcessor::ProcessBytes(const uint8_t* data, size_t len,
    UmpCallback callback)
{
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];

        // 1. Handle Real-Time Messages (MT=1) - Priority High
        // These can interrupt anything, including SysEx, without changing state.
        if (b >= 0xF8) {
            uint32_t mt1 = (0x1U << 28) | (static_cast<uint32_t>(group_) << 24) | (static_cast<uint32_t>(b) << 16);
            callback({ mt1 });
            continue;
        }

        // 2. Handle Status Bytes
        if (b >= 0x80) {
            // New status always interrupts Running Status accumulation
            cv_pos_ = 0;

            // -- Handle SysEx Start (0xF0) --
            if (b == 0xF0) {
                in_sysex_ = true;
                sysex_pos_ = 0;
                sysex_has_started_ = false;
                running_status_ = 0; // SysEx clears running status
                continue; // F0 is stripped, not added to data
            }

            // -- Handle SysEx End (0xF7) --
            if (b == 0xF7) {
                if (in_sysex_) {
                    FinalizeSysEx(callback);
                    in_sysex_ = false;
                }
                running_status_ = 0;
                continue; // F7 is stripped
            }

            // -- Handle Channel Voice / System Common --
            in_sysex_ = false; // Any non-realtime status breaks SysEx
            
            // F1-F6 are System Common, 80-EF are Channel Voice
            cv_buffer_[0] = b;
            cv_pos_ = 1;
            expected_len_ = GetExpectedDataLength(b);

            if (b < 0xF0) {
                running_status_ = b;
            } else {
                running_status_ = 0; // System Common clears running status
            }

            // Edge case: Some System messages might have 0 data bytes (e.g. Tune Request F6)
            if (expected_len_ == 0) {
                DispatchChannelMessage(callback);
                cv_pos_ = 0;
            }
        } else { // 3. Handle Data Bytes
            // -- SysEx Mode --
            if (in_sysex_) {
                ProcessSysExData(b, callback);
            } else {             // -- Channel/Common Mode --
                // Recover Running Status if buffer is empty
                if (cv_pos_ == 0 && running_status_ != 0) {
                    cv_buffer_[0] = running_status_;
                    cv_buffer_[1] = b;
                    cv_pos_ = 2;
                    expected_len_ = GetExpectedDataLength(running_status_);
                } else if (cv_pos_ > 0 && cv_pos_ < 3) {
                    cv_buffer_[cv_pos_++] = b;
                } else {
                    // Orphaned data byte, ignore
                    continue;
                }

                // Check completion
                if (cv_pos_ == (expected_len_ + 1)) {
                    DispatchChannelMessage(callback);
                    cv_pos_ = 0; // Reset for next message (keeping running_status_)
                }
            }
        }
    }
}

// --- Helper Functions ---

int UmpProcessor::GetExpectedDataLength(uint8_t status)
{
    if (status < 0xF0) {
        uint8_t type = status & 0xF0;
        if (type == 0xC0 || type == 0xD0) return 1;
        return 2;
    }
    // System Common
    switch (status) {
        case 0xF1: case 0xF3: return 1;
        case 0xF2: return 2;
        default: return 0; // F6, etc.
    }
}

void UmpProcessor::DispatchChannelMessage(UmpCallback callback)
{
    uint8_t status = cv_buffer_[0];
    uint32_t mt = (status < 0xF0) ? 0x2U : 0x1U; // MT=2 for Channel, MT=1 for System
    
    uint32_t w0 = (mt << 28) | (static_cast<uint32_t>(group_) << 24) | (static_cast<uint32_t>(status) << 16);
    
    // Add Data Byte 1
    if (expected_len_ >= 1) w0 |= (static_cast<uint32_t>(cv_buffer_[1]) << 8);
    // Add Data Byte 2
    if (expected_len_ == 2) w0 |= (static_cast<uint32_t>(cv_buffer_[2]));

    callback({ w0 });
}

// --- SysEx Logic (MT=3) ---

void UmpProcessor::ProcessSysExData(uint8_t byte, UmpCallback callback)
{
    if (sysex_pos_ < 6) {
        sysex_buffer_[sysex_pos_++] = byte;
    }

    // Buffer full? Dispatch intermediate packet
    if (sysex_pos_ == 6) {
        // Status: 0x1 (Start) if first packet, else 0x2 (Continue)
        uint8_t status = sysex_has_started_ ? 0x2 : 0x1;
        DispatchSysExPacket(callback, status, 6);
        
        sysex_pos_ = 0;
        sysex_has_started_ = true;
    }
}

void UmpProcessor::FinalizeSysEx(UmpCallback callback)
{
    // Determine Status:
    // If we haven't sent a Start packet yet -> 0x0 (Complete)
    // If we have sent a Start packet -> 0x3 (End)
    uint8_t status = sysex_has_started_ ? 0x3 : 0x0;
    
    DispatchSysExPacket(callback, status, sysex_pos_);
    
    sysex_pos_ = 0;
    sysex_has_started_ = false;
}

void UmpProcessor::DispatchSysExPacket(UmpCallback callback, uint8_t status_code, uint8_t byte_count)
{
    // Word 0: [MT=3 (4b)] [Group (4b)] [Status (4b)] [Count (4b)] [Data0 (8b)] [Data1 (8b)]
    uint32_t w0 = (0x3U << 28) | (static_cast<uint32_t>(group_) << 24) |
                  (static_cast<uint32_t>(status_code) << 20) |
                  (static_cast<uint32_t>(byte_count) << 16);
    
    if (byte_count > 0) w0 |= (static_cast<uint32_t>(sysex_buffer_[0]) << 8);
    if (byte_count > 1) w0 |= (static_cast<uint32_t>(sysex_buffer_[1]));

    // Word 1: [Data2] [Data3] [Data4] [Data5]
    uint32_t w1 = 0;
    if (byte_count > 2) w1 |= (static_cast<uint32_t>(sysex_buffer_[2]) << 24);
    if (byte_count > 3) w1 |= (static_cast<uint32_t>(sysex_buffer_[3]) << 16);
    if (byte_count > 4) w1 |= (static_cast<uint32_t>(sysex_buffer_[4]) << 8);
    if (byte_count > 5) w1 |= (static_cast<uint32_t>(sysex_buffer_[5]));

    callback({ w0, w1 });
}
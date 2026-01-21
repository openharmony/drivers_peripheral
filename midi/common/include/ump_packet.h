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

#ifndef UMP_PACKET_H
#define UMP_PACKET_H
#include <cstdint>
#include <initializer_list>
#include <algorithm>

/**
 * @brief Represents a Universal MIDI Packet (UMP).
 */
class UmpPacket {
public:
    static constexpr size_t MAX_WORD_COUNT = 4;
    /**
     * @brief Optimized constructor for single-word packets (MT=1, MT=2).
     * Usage: UmpPacket(0x20903C64)
     */
    explicit UmpPacket(uint32_t w0);

    /**
     * @brief Universal constructor for multi-word packets (MT=3, MT=F, etc.).
     * Usage: UmpPacket({w0, w1})
     */
    UmpPacket(std::initializer_list<uint32_t> words);

    uint32_t Word(size_t index) const;
    uint8_t WordCount() const;

private:
    uint32_t data_[MAX_WORD_COUNT] = { 0 }; // Zero-initialized by default
    uint8_t word_count_ = 0;
};
#endif
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

#include "ump_packet.h"

// Optimized constructor for the most common case (1 word)
UmpPacket::UmpPacket(uint32_t w0)
{
    data_[0] = w0;
    // data_[1]..[3] are already 0 via member initialization
    word_count_ = 1;
}

// Universal constructor for variable length
UmpPacket::UmpPacket(std::initializer_list<uint32_t> words)
{
    word_count_ = static_cast<uint8_t>(std::min(words.size(), MAX_WORD_COUNT));
    
    size_t i = 0;
    for (uint32_t w : words) {
        if (i < MAX_WORD_COUNT) data_[i++] = w;
    }
}

uint32_t UmpPacket::Word(size_t index) const
{
    return (index < MAX_WORD_COUNT) ? data_[index] : 0;
}

uint8_t UmpPacket::WordCount() const
{
    return word_count_;
}
/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "attributes.h"

#include <map>
#include <memory>

#include "iam_logger.h"
#include "securec.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
#define LOG_TAG "USER_AUTH_IMPL"
class Attributes::Impl {
public:
    Impl() = default;

    explicit Impl(const std::vector<uint8_t> &raw);

    Impl(const Impl &other) = delete;
    Impl &operator=(const Impl &other) = delete;

    Impl(Impl &&other) noexcept;
    Impl &operator=(Impl &&other) noexcept;

    virtual ~Impl() = default;

    bool SetUint64Value(AttributeKey attrKey, uint64_t attrValue);
    bool SetUint8ArrayValue(AttributeKey attrKey, const std::vector<uint8_t> &attrValue);

    bool GetUint64Value(AttributeKey attrKey, uint64_t &attrValue) const;
    bool GetUint8ArrayValue(AttributeKey attrKey, std::vector<uint8_t> &attrValue) const;
    std::vector<uint8_t> Serialize() const;
    std::vector<AttributeKey> GetKeys() const;

private:
    static constexpr uint32_t MAX_ATTR_LENGTH = 81920;
    static constexpr uint32_t MAX_ATTR_COUNT = 512;
    static bool EncodeUint64Value(uint64_t srcValue, std::vector<uint8_t> &dstValue);
    static bool EncodeUint32Value(uint32_t srcValue, std::vector<uint8_t> &dst);
    static bool EncodeUint8ArrayValue(const std::vector<uint8_t> &srcValue, std::vector<uint8_t> &dstValue);

    static bool DecodeUint64Value(const std::vector<uint8_t> &srcValue, uint64_t &dstValue);
    static bool DecodeUint8ArrayValue(const std::vector<uint8_t> &srcValue, std::vector<uint8_t> &dstValue);
    static bool CheckAttributeLength(const uint8_t *curr, const uint8_t *end, uint32_t length);
    std::map<AttributeKey, const std::vector<uint8_t>> map_;
};

Attributes::Impl::Impl(const std::vector<uint8_t> &raw)
{
    std::map<Attributes::AttributeKey, const std::vector<uint8_t>> out;

    const uint8_t *curr = &raw.front();
    const uint8_t *end = &raw.back() + sizeof(uint8_t);
    while (curr < end) {
        if (curr + sizeof(uint32_t) + sizeof(uint32_t) < curr) { // in case of out of range
            IAM_LOGE("out of pointer range");
            return;
        }

        if (curr + sizeof(uint32_t) + sizeof(uint32_t) > end) {
            IAM_LOGE("out of end range");
            return;
        }

        uint32_t type;
        if (memcpy_s(&type, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("type copy error");
            return;
        }
        curr += sizeof(uint32_t);

        uint32_t length;
        if (memcpy_s(&length, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("length copy error");
            return;
        }
        curr += sizeof(uint32_t);

        if (!CheckAttributeLength(curr, end, length)) {
            IAM_LOGE("check attribute length error");
            return;
        }

        std::vector<uint8_t> attrValue(length / sizeof(uint8_t));
        if (length != 0 && memcpy_s(attrValue.data(), attrValue.size() * sizeof(uint8_t), curr, length) != EOK) {
            IAM_LOGE("attrValue copy error, length = %{public}u", length);
            return;
        }

        auto ret = out.try_emplace(static_cast<Attributes::AttributeKey>(type), attrValue);
        if (!ret.second) {
            IAM_LOGE("emplace pair error, type is %{public}u", type);
            return;
        }

        if (out.size() > MAX_ATTR_COUNT) {
            IAM_LOGE("emplace pair error, size reach max");
            return;
        }

        IAM_LOGD("emplace pair success, type is %{public}u", type);
        curr += length;
    }

    map_.swap(out);
}

Attributes::Impl::Impl(Attributes::Impl &&other) noexcept : map_(std::move(other.map_))
{
}

Attributes::Impl &Attributes::Impl::operator=(Attributes::Impl &&other) noexcept
{
    map_ = std::move(other.map_);
    return *this;
}

bool Attributes::Impl::CheckAttributeLength(const uint8_t *curr, const uint8_t *end, uint32_t length)
{
    if (length % sizeof(uint8_t) != 0 || length > MAX_ATTR_LENGTH) {
        IAM_LOGE("length format error, length = %{public}u", length);
        return false;
    }
    if (length > end - curr) {
        IAM_LOGE("length too big, length = %{public}u", length);
        return false;
    }
    return true;
}

bool Attributes::Impl::SetUint64Value(AttributeKey attrKey, uint64_t attrValue)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint64Value(attrValue, dest)) {
        IAM_LOGE("EncodeUint64Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(attrKey, dest);
    return ret.second;
}

bool Attributes::Impl::SetUint8ArrayValue(AttributeKey attrKey, const std::vector<uint8_t> &attrValue)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint8ArrayValue(attrValue, dest)) {
        IAM_LOGE("EncodeUint8ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(attrKey, attrValue);
    return ret.second;
}

bool Attributes::Impl::GetUint64Value(AttributeKey attrKey, uint64_t &attrValue) const
{
    auto iter = map_.find(attrKey);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint64Value(iter->second, attrValue)) {
        IAM_LOGE("DecodeUint64Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint8ArrayValue(AttributeKey attrKey, std::vector<uint8_t> &attrValue) const
{
    auto iter = map_.find(attrKey);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint8ArrayValue(iter->second, attrValue)) {
        IAM_LOGE("DecodeUint8ArrayValue error");
        return false;
    }
    return true;
}

std::vector<uint8_t> Attributes::Impl::Serialize() const
{
    uint32_t size = 0;
    for (const auto &[attrKey, attrValue] : map_) {
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += attrValue.size();
    }
    std::vector<uint8_t> buffer;
    buffer.reserve(size);

    for (const auto &[attrKey, attrValue] : map_) {
        std::vector<uint8_t> type;
        std::vector<uint8_t> length;
        if (!EncodeUint32Value(attrKey, type)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value attrKey error");
            break;
        }
        if (!EncodeUint32Value(attrValue.size() * sizeof(uint8_t), length)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value attrValue error");
            break;
        }
        buffer.insert(buffer.end(), type.begin(), type.end());
        buffer.insert(buffer.end(), length.begin(), length.end());
        buffer.insert(buffer.end(), attrValue.begin(), attrValue.end());
    }
    return buffer;
}

std::vector<Attributes::AttributeKey> Attributes::Impl::GetKeys() const
{
    std::vector<Attributes::AttributeKey> keys;
    keys.reserve(map_.size());
    for (auto const &item : map_) {
        keys.push_back(item.first);
    }
    return keys;
}

bool Attributes::Impl::EncodeUint64Value(uint64_t srcValue, std::vector<uint8_t> &dstValue)
{
    std::vector<uint8_t> out(sizeof(uint64_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &srcValue, sizeof(srcValue)) != EOK) {
        return false;
    }
    dstValue.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint32Value(uint32_t srcValue, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint32_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &srcValue, sizeof(srcValue)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint8ArrayValue(const std::vector<uint8_t> &srcValue, std::vector<uint8_t> &dstValue)
{
    if (srcValue.size() > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(srcValue);
    dstValue.swap(out);
    return true;
}

bool Attributes::Impl::DecodeUint64Value(const std::vector<uint8_t> &srcValue, uint64_t &dstValue)
{
    if (srcValue.size() * sizeof(uint8_t) != sizeof(uint64_t)) {
        return false;
    }

    if (memcpy_s(&dstValue, sizeof(dstValue), srcValue.data(), srcValue.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool Attributes::Impl::DecodeUint8ArrayValue(const std::vector<uint8_t> &srcValue, std::vector<uint8_t> &dstValue)
{
    std::vector<uint8_t> out(srcValue);
    dstValue.swap(out);
    return true;
}

Attributes::Attributes() : impl_(new (std::nothrow) Attributes::Impl())
{
}

Attributes::Attributes(const std::vector<uint8_t> &raw) : impl_(new (std::nothrow) Attributes::Impl(raw))
{
}

Attributes::Attributes(Attributes &&other) noexcept : impl_(std::move(other.impl_))
{
}

Attributes &Attributes::operator=(Attributes &&other) noexcept
{
    impl_ = std::move(other.impl_);
    return *this;
}

Attributes::~Attributes()
{
    impl_ = nullptr;
};

bool Attributes::SetUint64Value(AttributeKey attrKey, uint64_t attrValue)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint64Value(attrKey, attrValue);
}

bool Attributes::SetUint8ArrayValue(AttributeKey attrKey, const std::vector<uint8_t> &attrValue)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint8ArrayValue(attrKey, attrValue);
}

bool Attributes::GetUint64Value(AttributeKey attrKey, uint64_t &attrValue) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint64Value(attrKey, attrValue);
}

bool Attributes::GetUint8ArrayValue(AttributeKey attrKey, std::vector<uint8_t> &attrValue) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint8ArrayValue(attrKey, attrValue);
}

std::vector<uint8_t> Attributes::Serialize() const
{
    if (!impl_) {
        return {};
    }
    return impl_->Serialize();
}

std::vector<Attributes::AttributeKey> Attributes::GetKeys() const
{
    if (!impl_) {
        return {};
    }
    return impl_->GetKeys();
}
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS
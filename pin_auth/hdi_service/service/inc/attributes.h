/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IAM_ATTRIBUTES_H
#define IAM_ATTRIBUTES_H

#include <memory>
#include <vector>

namespace OHOS {
namespace HDI {
namespace PinAuth {
class Attributes final {
public:
    enum AttributeKey : uint32_t {
        /* Root tag */
        AUTH_ROOT = 100000,
        /* Tag of data */
        AUTH_DATA = 100020,
        /* Pin expired sys time. */
        AUTH_EXPIRED_SYS_TIME = 100034,
    };

    Attributes();
    explicit Attributes(const std::vector<uint8_t> &raw);
    Attributes(const Attributes &other) = delete;
    Attributes &operator=(const Attributes &other) = delete;
    Attributes(Attributes &&other) noexcept;
    Attributes &operator=(Attributes &&other) noexcept;
    virtual ~Attributes();

    bool SetUint64Value(AttributeKey attrKey, uint64_t attrValue);
    bool SetUint8ArrayValue(AttributeKey attrKey, const std::vector<uint8_t> &attrValue);
    bool GetUint64Value(AttributeKey attrKey, uint64_t &attrValue) const;
    bool GetUint8ArrayValue(AttributeKey attrKey, std::vector<uint8_t> &attrValue) const;
    std::vector<uint8_t> Serialize() const;
    std::vector<AttributeKey> GetKeys() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

#endif // IAM_ATTRIBUTES_H
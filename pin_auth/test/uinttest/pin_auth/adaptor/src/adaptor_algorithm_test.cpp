/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "adaptor_algorithm_test.h"

#include <gtest/gtest.h>

#include "adaptor_algorithm.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void AdaptorAlgorithmTest::SetUpTestCase()
{
}

void AdaptorAlgorithmTest::TearDownTestCase()
{
}

void AdaptorAlgorithmTest::SetUp()
{
}

void AdaptorAlgorithmTest::TearDown()
{
}

/**
 * @tc.name: ase_encode_null
 * @tc.desc: verify Aes256GcmEncryptNoPadding
 * @tc.type: FUNC
 * @tc.require: issueI5NYCT
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmAesEnCode1, TestSize.Level1)
{
    Buffer *cipherInfo = Aes256GcmEncryptNoPadding(nullptr, nullptr);
    EXPECT_EQ(cipherInfo, nullptr);
    DestoryBuffer(cipherInfo);
}

/**
 * @tc.name: ase_encode_failed
 * @tc.desc: verify Aes256GcmEncryptNoPadding
 * @tc.type: FUNC
 * @tc.require: issueI5NYCT
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmAesEnCode2, TestSize.Level1)
{
    Buffer *plaintext = CreateBufferBySize(20);
    ASSERT_NE(plaintext, nullptr);
    Buffer *key = CreateBufferBySize(10);
    ASSERT_NE(key, nullptr);
    Buffer *cipherInfo = Aes256GcmEncryptNoPadding(plaintext, key);
    EXPECT_EQ(cipherInfo, nullptr);
    DestoryBuffer(plaintext);
    DestoryBuffer(key);
    DestoryBuffer(cipherInfo);
}

/**
 * @tc.name: ase_encode_success
 * @tc.desc: verify Aes256GcmEncryptNoPadding
 * @tc.type: FUNC
 * @tc.require: issueI5NYCT
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmAesValid, TestSize.Level1)
{
    Buffer *plaintext1 = CreateBufferBySize(64);
    ASSERT_NE(plaintext1, nullptr);
    (void)SecureRandom(plaintext1->buf, plaintext1->maxSize);
    plaintext1->contentSize = plaintext1->maxSize;
    Buffer *key = CreateBufferBySize(AES256_KEY_SIZE);
    ASSERT_NE(key, nullptr);
    (void)SecureRandom(key->buf, key->maxSize);
    key->contentSize = key->maxSize;
    Buffer *cipherInfo = Aes256GcmEncryptNoPadding(plaintext1, key);
    ASSERT_NE(cipherInfo, nullptr);
    Buffer *plaintext2 = Aes256GcmDecryptNoPadding(cipherInfo, key);
    ASSERT_NE(plaintext2, nullptr);
    bool isSame = CompareBuffer(plaintext1, plaintext2);
    EXPECT_EQ(isSame, true);
    DestoryBuffer(plaintext1);
    DestoryBuffer(plaintext2);
    DestoryBuffer(key);
    DestoryBuffer(cipherInfo);
}

/**
 * @tc.name: device_key
 * @tc.desc: verify DeriveDeviceKey
 * @tc.type: FUNC
 * @tc.require: issueI5NYDJ
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmDeriveDeviceKey, TestSize.Level1)
{
    Buffer *secret = CreateBufferBySize(SECRET_SIZE);
    ASSERT_NE(secret, nullptr);
    (void)SecureRandom(secret->buf, secret->maxSize);
    secret->contentSize = secret->maxSize;
    Buffer *key = DeriveDeviceKey(secret);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->contentSize, SHA256_DIGEST_SIZE);
    DestoryBuffer(secret);
    DestoryBuffer(key);
}

/**
 * @tc.name: hkdf
 * @tc.desc: verify Hkdf
 * @tc.type: FUNC
 * @tc.require: issueI5NYDJ
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmHkdf, TestSize.Level1)
{
    Buffer *salt = CreateBufferBySize(HKDF_SALT_SIZE);
    ASSERT_NE(salt, nullptr);
    (void)SecureRandom(salt->buf, salt->maxSize);
    salt->contentSize = salt->maxSize;
    Buffer *rootKey = CreateBufferBySize(AES256_KEY_SIZE);
    ASSERT_NE(rootKey, nullptr);
    (void)SecureRandom(rootKey->buf, rootKey->maxSize);
    rootKey->contentSize = rootKey->maxSize;
    Buffer *key = Hkdf(salt, rootKey);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->contentSize, SHA256_DIGEST_SIZE);
    DestoryBuffer(salt);
    DestoryBuffer(rootKey);
    DestoryBuffer(key);
}

/**
 * @tc.name: sha256
 * @tc.desc: verify Sha256Adaptor
 * @tc.type: FUNC
 * @tc.require: issueI5NYDJ
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmSha256, TestSize.Level1)
{
    Buffer *data = CreateBufferBySize(64);
    ASSERT_NE(data, nullptr);
    (void)SecureRandom(data->buf, data->maxSize);
    data->contentSize = data->maxSize;
    Buffer *key = Sha256Adaptor(data);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->contentSize, SHA256_DIGEST_SIZE);
    DestoryBuffer(data);
    DestoryBuffer(key);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

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
 * @tc.name: KeyPair test
 * @tc.desc: verify KeyPair
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorAlgorithmTest, KeyPair_Test, TestSize.Level1)
{
    DestroyKeyPair(nullptr);

    std::vector<uint8_t> dataTest(32, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], 32);
    EXPECT_NE(data, nullptr);
    KeyPair keyPair2 = {};
    keyPair2.pubKey = nullptr;
    keyPair2.priKey = CopyBuffer(data);
    EXPECT_NE(keyPair2.priKey, nullptr);
    bool result = IsEd25519KeyPairValid(&keyPair2);
    EXPECT_EQ(result, false);
    DestroyBuffer(keyPair2.priKey);

    KeyPair keyPair3 = {};
    keyPair3.priKey = nullptr;
    keyPair3.pubKey = CopyBuffer(data);
    EXPECT_NE(keyPair3.pubKey, nullptr);
    result = IsEd25519KeyPairValid(&keyPair3);
    EXPECT_EQ(result, false);
    DestroyBuffer(keyPair3.pubKey);
    DestroyBuffer(data);

    KeyPair *keyPair4 = GenerateEd25519KeyPair();
    EXPECT_NE(keyPair4, nullptr);
    result = IsEd25519KeyPairValid(keyPair4);
    EXPECT_EQ(result, true);
    DestroyKeyPair(keyPair4);
}

/**
 * @tc.name: Ed25519Sign test
 * @tc.desc: sign Ed25519
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorAlgorithmTest, Ed25519Sign_Test, TestSize.Level1)
{
    constexpr uint32_t keyLen = 32;
    std::vector<uint8_t> dataTest(keyLen, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], keyLen);
    EXPECT_NE(data, nullptr);
    Buffer *signContent = nullptr;
    KeyPair *keyPair = GenerateEd25519KeyPair();
    EXPECT_NE(keyPair, nullptr);

    int32_t result = Ed25519Sign(nullptr, data, &signContent);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Sign(keyPair, nullptr, &signContent);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Sign(keyPair, data, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Sign(keyPair, data, &signContent);
    EXPECT_EQ(result, RESULT_SUCCESS);

    DestroyBuffer(signContent);
    DestroyKeyPair(keyPair);
    DestroyBuffer(data);
}

/**
 * @tc.name: Ed25519Verify test
 * @tc.desc: verify Ed25519
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorAlgorithmTest, Ed25519Verify_Test, TestSize.Level1)
{
    constexpr uint32_t constLen = 64;
    std::vector<uint8_t> dataTest(constLen, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], constLen);
    KeyPair *keyPair = GenerateEd25519KeyPair();
    EXPECT_NE(keyPair, nullptr);
    Buffer *signContent = nullptr;

    int32_t result = Ed25519Sign(keyPair, data, &signContent);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = Ed25519Verify(nullptr, data, signContent);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Verify(keyPair->pubKey, nullptr, signContent);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Verify(keyPair->pubKey, data, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = Ed25519Verify(keyPair->priKey, data, signContent);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);

    result = Ed25519Verify(keyPair->pubKey, data, signContent);
    EXPECT_EQ(result, RESULT_SUCCESS);

    DestroyBuffer(signContent);
    DestroyKeyPair(keyPair);
    DestroyBuffer(data);
}

/**
 * @tc.name: ase_encode_null
 * @tc.desc: verify Aes256GcmEncryptNoPadding
 * @tc.type: FUNC
 * @tc.require: issueI5NYCT
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmAesEnCode1, TestSize.Level1)
{
    int32_t result = AesGcm256Encrypt(nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
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
    int32_t result = AesGcm256Encrypt(plaintext, nullptr, nullptr, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    DestroyBuffer(plaintext);
}

static Buffer *RandomBuffer(uint32_t size)
{
    Buffer *buffer = CreateBufferBySize(size);
    if (buffer == NULL) {
        return buffer;
    }
    (void)SecureRandom(buffer->buf, buffer->maxSize);
    buffer->contentSize = buffer->maxSize;
    return buffer;
}

/**
 * @tc.name: ase_encode_success
 * @tc.desc: verify Aes256GcmEncryptNoPadding
 * @tc.type: FUNC
 * @tc.require: issueI5NYCT
 */
HWTEST_F(AdaptorAlgorithmTest, AdaptorAlgorithmAesValid, TestSize.Level1)
{
    Buffer *plaintext1 = RandomBuffer(64);
    ASSERT_NE(plaintext1, nullptr);
    AesGcmParam param = {};
    param.key = RandomBuffer(AES_GCM_256_KEY_SIZE);
    ASSERT_NE(param.key, nullptr);
    param.iv = RandomBuffer(AES_GCM_256_IV_SIZE);
    ASSERT_NE(param.iv, nullptr);
    Buffer *cipherText = NULL;
    Buffer *tag = NULL;
    int32_t result = AesGcm256Encrypt(plaintext1, &param, &cipherText, &tag);
    EXPECT_EQ(result, RESULT_SUCCESS);

    Buffer *plaintext2 = NULL;
    result = AesGcm256Decrypt(cipherText, &param, tag, &plaintext2);
    EXPECT_EQ(result, RESULT_SUCCESS);

    bool isSame = CompareBuffer(plaintext1, plaintext2);
    EXPECT_EQ(isSame, true);

    DestroyBuffer(plaintext1);
    DestroyBuffer(param.key);
    DestroyBuffer(param.iv);
    DestroyBuffer(cipherText);
    DestroyBuffer(tag);
    DestroyBuffer(plaintext2);
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
    constexpr uint32_t pinDataLen = 64;
    Buffer *pinData = CreateBufferBySize(pinDataLen);
    ASSERT_NE(pinData, nullptr);
    (void)SecureRandom(pinData->buf, pinData->maxSize);
    pinData->contentSize = pinData->maxSize;
    Buffer *key = DeriveDeviceKey(pinData, secret);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->contentSize, SHA256_DIGEST_SIZE);
    DestroyBuffer(key);
    DestroyBuffer(pinData);
    DestroyBuffer(secret);
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
    Buffer *rootKey = CreateBufferBySize(AES_GCM_256_KEY_SIZE);
    ASSERT_NE(rootKey, nullptr);
    (void)SecureRandom(rootKey->buf, rootKey->maxSize);
    rootKey->contentSize = rootKey->maxSize;
    Buffer *key = Hkdf(salt, rootKey);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->contentSize, SHA256_DIGEST_SIZE);
    DestroyBuffer(salt);
    DestroyBuffer(rootKey);
    DestroyBuffer(key);
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
    DestroyBuffer(data);
    DestroyBuffer(key);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

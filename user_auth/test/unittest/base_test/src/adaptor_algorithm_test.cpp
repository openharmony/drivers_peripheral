/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "adaptor_algorithm.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
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
HWTEST_F(AdaptorAlgorithmTest, KeyPair_Test, TestSize.Level0)
{
    DestoryKeyPair(nullptr);

    constexpr uint32_t KEY_LEN = 32;
    std::vector<uint8_t> dataTest(KEY_LEN, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], KEY_LEN);
    EXPECT_NE(data, nullptr);
    KeyPair keyPair2 = {};
    keyPair2.pubKey = nullptr;
    keyPair2.priKey = CopyBuffer(data);
    EXPECT_NE(keyPair2.priKey, nullptr);
    bool result = IsEd25519KeyPairValid(&keyPair2);
    EXPECT_EQ(result, false);
    DestoryBuffer(keyPair2.priKey);

    KeyPair keyPair3 = {};
    keyPair3.priKey = nullptr;
    keyPair3.pubKey = CopyBuffer(data);
    EXPECT_NE(keyPair3.pubKey, nullptr);
    result = IsEd25519KeyPairValid(&keyPair3);
    EXPECT_EQ(result, false);
    DestoryBuffer(keyPair3.pubKey);
    DestoryBuffer(data);

    KeyPair *keyPair4 = GenerateEd25519KeyPair();
    EXPECT_NE(keyPair4, nullptr);
    result = IsEd25519KeyPairValid(keyPair4);
    EXPECT_EQ(result, true);
    DestoryKeyPair(keyPair4);
}

/**
 * @tc.name: Ed25519Sign test
 * @tc.desc: sign Ed25519
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorAlgorithmTest, Ed25519Sign_Test, TestSize.Level0)
{
    constexpr uint32_t KEY_LEN = 32;
    std::vector<uint8_t> dataTest(KEY_LEN, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], KEY_LEN);
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

    DestoryBuffer(signContent);
    DestoryKeyPair(keyPair);
    DestoryBuffer(data);
}

/**
 * @tc.name: Ed25519Verify test
 * @tc.desc: verify Ed25519
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorAlgorithmTest, Ed25519Verify_Test, TestSize.Level0)
{
    constexpr uint32_t KEY_LEN = 64;
    std::vector<uint8_t> dataTest(KEY_LEN, 1);
    Buffer *data = CreateBufferByData(&dataTest[0], KEY_LEN);
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

    DestoryBuffer(signContent);
    DestoryKeyPair(keyPair);
    DestoryBuffer(data);
}

HWTEST_F(AdaptorAlgorithmTest, TestHmacSha256, TestSize.Level0)
{
    Buffer *hmacKey = nullptr;
    Buffer *data = nullptr;
    Buffer **hmac = nullptr;
    EXPECT_EQ(HmacSha256(hmacKey, data, hmac), RESULT_BAD_PARAM);
    Buffer *temp = nullptr;
    hmac = &temp;
    EXPECT_EQ(HmacSha256(hmacKey, data, hmac), RESULT_GENERAL_ERROR);
}

HWTEST_F(AdaptorAlgorithmTest, TestSecureRandom, TestSize.Level0)
{
    uint8_t *buffer = nullptr;
    EXPECT_EQ(SecureRandom(buffer, 10), RESULT_BAD_PARAM);
    uint8_t num = 0;
    buffer = &num;
    EXPECT_EQ(SecureRandom(buffer, 1), RESULT_SUCCESS);
}

HWTEST_F(AdaptorAlgorithmTest, TestAesGcmEncrypt, TestSize.Level0)
{
    Buffer *plaintext = nullptr;
    AesGcmParam aesGcmParam = {};
    Buffer *ciphertext = nullptr;
    Buffer *tag = nullptr;
    constexpr uint32_t PLAIN_TEXT_LEN = 1001;
    constexpr uint32_t PLAIN_TEXT_ERRLEN = 100;
    constexpr uint32_t GCM_KEY_LEN = 32;
    constexpr uint32_t GCM_IV_LEN = 12;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_BAD_PARAM);
    plaintext = CreateBufferBySize(PLAIN_TEXT_LEN);
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_BAD_PARAM);
    plaintext->contentSize = PLAIN_TEXT_LEN;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_BAD_PARAM);
    plaintext->contentSize = PLAIN_TEXT_ERRLEN;
    EXPECT_EQ(AesGcmEncrypt(plaintext, nullptr, &ciphertext, &tag), RESULT_BAD_PARAM);
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_BAD_PARAM);
    aesGcmParam.key = CreateBufferBySize(GCM_KEY_LEN);
    aesGcmParam.key->contentSize = GCM_KEY_LEN;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_BAD_PARAM);
    aesGcmParam.iv = CreateBufferBySize(GCM_IV_LEN);
    aesGcmParam.iv->contentSize = GCM_IV_LEN;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, nullptr, &tag), RESULT_BAD_PARAM);
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, nullptr), RESULT_BAD_PARAM);
    DestoryBuffer(plaintext);
    DestoryBuffer(aesGcmParam.key);
    DestoryBuffer(aesGcmParam.iv);
}

HWTEST_F(AdaptorAlgorithmTest, TestAesGcmDecrypt, TestSize.Level0)
{
    Buffer *ciphertext = nullptr;
    AesGcmParam aesGcmParam = {};
    Buffer *plaintext = nullptr;
    Buffer *tag = nullptr;
    constexpr uint32_t PLAIN_TEXT_LEN = 1001;
    constexpr uint32_t PLAIN_TEXT_ERRLEN = 100;
    constexpr uint32_t GCM_KEY_LEN = 32;
    constexpr uint32_t GCM_IV_LEN = 12;
    constexpr uint32_t GCM_TAG_LEN = 16;
    constexpr uint32_t GCM_AAD_LEN = 12;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    ciphertext = CreateBufferBySize(PLAIN_TEXT_LEN);
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    ciphertext->contentSize = PLAIN_TEXT_LEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    ciphertext->contentSize = PLAIN_TEXT_ERRLEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, nullptr, tag, &plaintext), RESULT_BAD_PARAM);
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    aesGcmParam.key = CreateBufferBySize(GCM_KEY_LEN);
    aesGcmParam.key->contentSize = GCM_KEY_LEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    aesGcmParam.iv = CreateBufferBySize(GCM_IV_LEN);
    aesGcmParam.iv->contentSize = GCM_IV_LEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_BAD_PARAM);
    tag = CreateBufferBySize(GCM_TAG_LEN);
    tag->contentSize = GCM_TAG_LEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, nullptr), RESULT_BAD_PARAM);
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_GENERAL_ERROR);
    aesGcmParam.aad = CreateBufferBySize(GCM_AAD_LEN);
    aesGcmParam.aad->contentSize = GCM_AAD_LEN;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext), RESULT_GENERAL_ERROR);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    DestoryBuffer(aesGcmParam.key);
    DestoryBuffer(aesGcmParam.iv);
    DestoryBuffer(aesGcmParam.aad);
}

HWTEST_F(AdaptorAlgorithmTest, TestAesGcm, TestSize.Level0)
{
    constexpr uint32_t CONTEXT_SIZE = 100;
    constexpr uint32_t GCM_KEY_SIZE = 32;
    constexpr uint32_t GCM_IV_SIZE = 12;
    constexpr uint32_t GCM_AAD_LEN = 12;
    Buffer *plaintext = CreateBufferBySize(CONTEXT_SIZE);
    plaintext->contentSize = CONTEXT_SIZE;
    AesGcmParam aesGcmParam = {};
    aesGcmParam.key = CreateBufferBySize(GCM_KEY_SIZE);
    aesGcmParam.key->contentSize = GCM_KEY_SIZE;
    aesGcmParam.iv = CreateBufferBySize(GCM_IV_SIZE);
    aesGcmParam.iv->contentSize = GCM_IV_SIZE;
    Buffer *ciphertext = nullptr;
    Buffer *tag = nullptr;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_SUCCESS);
    Buffer *plaintext1 = nullptr;
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext1), RESULT_SUCCESS);
    EXPECT_EQ(CompareBuffer(plaintext, plaintext1), true);
    DestoryBuffer(ciphertext);
    ciphertext = nullptr;
    DestoryBuffer(tag);
    tag = nullptr;
    DestoryBuffer(plaintext1);
    plaintext1 = nullptr;
    aesGcmParam.aad = CreateBufferBySize(GCM_AAD_LEN);
    aesGcmParam.aad->contentSize = GCM_AAD_LEN;
    EXPECT_EQ(AesGcmEncrypt(plaintext, &aesGcmParam, &ciphertext, &tag), RESULT_SUCCESS);
    EXPECT_EQ(AesGcmDecrypt(ciphertext, &aesGcmParam, tag, &plaintext1), RESULT_SUCCESS);
    EXPECT_EQ(CompareBuffer(plaintext, plaintext1), true);
    DestoryBuffer(plaintext);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    DestoryBuffer(plaintext1);
    DestoryBuffer(aesGcmParam.key);
    DestoryBuffer(aesGcmParam.iv);
    DestoryBuffer(aesGcmParam.aad);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

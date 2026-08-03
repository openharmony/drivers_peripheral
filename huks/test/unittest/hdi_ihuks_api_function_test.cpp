/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <vector>
#include <unistd.h>
#include <securec.h>

#include "v1_2/ihuks.h"
#include "v1_2/ihuks_types.h"
#include "huks_sa_type.h"
#include "huks_hdi_test_util.h"

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;
namespace Unittest::HuksHdiTest {
static struct IHuks *g_huksHdiProxy = nullptr;

static const char *PROCESS_NAME_STRING = "hks_hdi";
static const struct HksBlob g_processName = { strlen(PROCESS_NAME_STRING), (uint8_t *)PROCESS_NAME_STRING };
const char *IMPORT_KEY_ALIAS = "importKeyAlias";
const char *GENERATE_KEY_ALIAS = "generateKeyAlias";
static uint8_t g_nonce[16] = {0};
static uint8_t g_aad[16] = {0};
static const uint8_t g_importKey[] = {
    0x17, 0xD6, 0x23, 0xCB, 0xA7, 0x05, 0x60, 0x22, 0xC1, 0x35, 0xCD, 0x3F, 0x30, 0x2D, 0xF6, 0x31,
};

static struct HksParam g_aes128GcmGenImportParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_GCM },
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG,   .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    { .tag = HKS_TAG_PROCESS_NAME,       .blob = g_processName },
};

static struct HksParam g_aes128GcmInitParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_GCM },
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_ASSOCIATED_DATA,    .blob = { .size = sizeof(g_aad), .data = g_aad } },
    { .tag = HKS_TAG_NONCE,              .blob = { .size = sizeof(g_nonce), .data = g_nonce } },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG,   .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    { .tag = HKS_TAG_PROCESS_NAME,       .blob = g_processName },
};

class HuksHdiApiTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HuksHdiApiTest::SetUpTestCase(void)
{
    g_huksHdiProxy = IHuksGetInstance("hdi_service", true);
    int32_t ret = g_huksHdiProxy->ModuleInit(g_huksHdiProxy);
    HUKS_TEST_LOG_I("ModuleInit = %d", ret);
}

void HuksHdiApiTest::TearDownTestCase(void)
{
    if (g_huksHdiProxy != nullptr) {
        IHuksReleaseInstance("hdi_service", g_huksHdiProxy, true);
        g_huksHdiProxy = nullptr;
    }
}

void HuksHdiApiTest::SetUp()
{
}

void HuksHdiApiTest::TearDown()
{
}

#define HKS_HDI_DEFAULT_PARAM_SET_SIZE 1024

static int32_t HksHdiInitParamSet(struct HksParamSet **paramSet)
{
    *paramSet = static_cast<struct HksParamSet *>(malloc(HKS_HDI_DEFAULT_PARAM_SET_SIZE));
    if (*paramSet == nullptr) {
        return HUKS_FAILURE;
    }
    (*paramSet)->paramsCnt = 0;
    (*paramSet)->paramSetSize = sizeof(struct HksParamSet);
    return HUKS_SUCCESS;
}

static int32_t HksHdiAddParams(struct HksParamSet *paramSet,
    const struct HksParam *params, uint32_t paramCnt)
{
    for (uint32_t i = 0; i < paramCnt; i++) {
        if (memcpy_s(&paramSet->params[paramSet->paramsCnt], sizeof(struct HksParam),
            &params[i], sizeof(struct HksParam)) != EOK) {
            return HUKS_FAILURE;
        }
        paramSet->paramSetSize += sizeof(struct HksParam);
        if ((params[i].tag & HKS_TAG_TYPE_MASK) == HKS_TAG_TYPE_BYTES) {
            paramSet->paramSetSize += params[i].blob.size;
        }
        paramSet->paramsCnt++;
    }
    return HUKS_SUCCESS;
}

static int32_t HksHdiBuildParamSet(struct HksParamSet **paramSet)
{
    uint32_t size = (*paramSet)->paramSetSize;
    uint32_t offset = sizeof(struct HksParamSet) + sizeof(struct HksParam) * (*paramSet)->paramsCnt;
    for (uint32_t i = 0; i < (*paramSet)->paramsCnt; i++) {
        if (((*paramSet)->params[i].tag & HKS_TAG_TYPE_MASK) == HKS_TAG_TYPE_BYTES) {
            if (memcpy_s((uint8_t *)(*paramSet) + offset, size - offset,
                (*paramSet)->params[i].blob.data, (*paramSet)->params[i].blob.size) != EOK) {
                return HUKS_FAILURE;
            }
            (*paramSet)->params[i].blob.data = (uint8_t *)(*paramSet) + offset;
            offset += (*paramSet)->params[i].blob.size;
        }
    }
    return HUKS_SUCCESS;
}

static void HksHdiFreeParamSet(struct HksParamSet **paramSet)
{
    if (paramSet != nullptr) {
        free(*paramSet);
        *paramSet = nullptr;
    }
}

static int32_t HksHdiBuildParamSetWithParams(struct HksParamSet **paramSet,
    const struct HksParam *params, uint32_t paramCnt)
{
    int32_t ret = HksHdiInitParamSet(paramSet);
    if (ret != HUKS_SUCCESS) {
        return ret;
    }
    ret = HksHdiAddParams(*paramSet, params, paramCnt);
    if (ret != HUKS_SUCCESS) {
        return ret;
    }
    ret = HksHdiBuildParamSet(paramSet);
    return ret;
}

/**
 * @tc.name: HuksHdiApiTest.HdiFuncPointerTest001
 * @tc.desc: Test hdi func pointer whether nullptr;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiTest, HdiFuncPointerTest001, TestSize.Level0)
{
    ASSERT_NE(g_huksHdiProxy, nullptr);
    ASSERT_NE(g_huksHdiProxy->ModuleInit, nullptr);
    ASSERT_NE(g_huksHdiProxy->ModuleDestroy, nullptr);
    ASSERT_NE(g_huksHdiProxy->GenerateKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->ImportKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->ImportWrappedKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->ExportPublicKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->Init, nullptr);
    ASSERT_NE(g_huksHdiProxy->Update, nullptr);
    ASSERT_NE(g_huksHdiProxy->Finish, nullptr);
    ASSERT_NE(g_huksHdiProxy->Abort, nullptr);
    ASSERT_NE(g_huksHdiProxy->CheckKeyValidity, nullptr);
    ASSERT_NE(g_huksHdiProxy->AttestKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->GenerateRandom, nullptr);
    ASSERT_NE(g_huksHdiProxy->Sign, nullptr);
    ASSERT_NE(g_huksHdiProxy->Verify, nullptr);
    ASSERT_NE(g_huksHdiProxy->Encrypt, nullptr);
    ASSERT_NE(g_huksHdiProxy->Decrypt, nullptr);
    ASSERT_NE(g_huksHdiProxy->AgreeKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->DeriveKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->Mac, nullptr);
    ASSERT_NE(g_huksHdiProxy->UpgradeKey, nullptr);
    ASSERT_NE(g_huksHdiProxy->GetVersion, nullptr);
}

/**
 * @tc.name: HuksHdiApiTest.ApiPassthroughTest001
 * @tc.desc: Test Generate key with current software huks driver;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiTest, ApiPassthroughTest001, TestSize.Level0)
{
    ASSERT_NE(g_huksHdiProxy, nullptr);
    ASSERT_NE(g_huksHdiProxy->GenerateKey, nullptr);

    uint8_t keyBuff[1] = {0};
    static struct HuksBlob key = {
        .data = keyBuff,
        .dataLen = sizeof(keyBuff)
    };
    struct HuksBlob keyAlias = {
        .data = (uint8_t *)GENERATE_KEY_ALIAS,
        .dataLen = sizeof(GENERATE_KEY_ALIAS)
    };
    
    struct HksParamSet *hksParamSet = nullptr;
    int ret = HksHdiBuildParamSetWithParams(&hksParamSet, g_aes128GcmGenImportParams,
        sizeof(g_aes128GcmGenImportParams) / sizeof(g_aes128GcmGenImportParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);
    struct HuksParamSet paramSet = {
        .data = (uint8_t *)hksParamSet,
        .dataLen = hksParamSet->paramSetSize
    };
    uint8_t outKeyBuffer[512];
    struct HuksBlob outKey = {
        .data = outKeyBuffer,
        .dataLen = sizeof(outKeyBuffer)
    };
    ret = g_huksHdiProxy->GenerateKey(g_huksHdiProxy, &keyAlias, &paramSet, &key, &outKey);
    HksHdiFreeParamSet(&hksParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);
}

/**
 * @tc.name: HuksHdiApiTest.ApiPassthroughTest002
 * @tc.desc: Test Import key with current software huks driver(hardcoded root key);
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiTest, ApiPassthroughTest002, TestSize.Level0)
{
    ASSERT_NE(g_huksHdiProxy, nullptr);
    ASSERT_NE(g_huksHdiProxy->ImportKey, nullptr);

    struct HuksBlob keyAlias = {
        .data = (uint8_t *)IMPORT_KEY_ALIAS,
        .dataLen = sizeof(IMPORT_KEY_ALIAS)
    };

    struct HuksBlob key = {
        .data = (uint8_t *)g_importKey,
        .dataLen = sizeof(g_importKey)
    };

    struct HksParamSet *hksParamSet = nullptr;
    int ret = HksHdiBuildParamSetWithParams(&hksParamSet, g_aes128GcmGenImportParams,
        sizeof(g_aes128GcmGenImportParams) / sizeof(g_aes128GcmGenImportParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);
    struct HuksParamSet paramSet = {
        .data = (uint8_t *)hksParamSet,
        .dataLen = hksParamSet->paramSetSize
    };
    uint8_t outKeyBuffer[512];
    struct HuksBlob outKey = {
        .data = outKeyBuffer,
        .dataLen = sizeof(outKeyBuffer)
    };
    ret = g_huksHdiProxy->ImportKey(g_huksHdiProxy, &keyAlias, &key, &paramSet, &outKey);
    HksHdiFreeParamSet(&hksParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);
}

/**
 * @tc.name: HuksHdiApiTest.ApiPassthroughTest003
 * @tc.desc: Test init key with current software huks driver(hardcoded root key);
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiTest, ApiPassthroughTest003, TestSize.Level0)
{
    ASSERT_NE(g_huksHdiProxy, nullptr);
    ASSERT_NE(g_huksHdiProxy->Init, nullptr);
    struct HksParamSet *hksParamSet = nullptr;
    uint8_t keyBuff[1] = {0};
    static struct HuksBlob key = { .data = keyBuff, .dataLen = sizeof(keyBuff) };
    struct HuksBlob keyAlias = { .data = (uint8_t *)GENERATE_KEY_ALIAS, .dataLen = sizeof(GENERATE_KEY_ALIAS) };

    int ret = HksHdiBuildParamSetWithParams(&hksParamSet, g_aes128GcmGenImportParams,
        sizeof(g_aes128GcmGenImportParams) / sizeof(g_aes128GcmGenImportParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HuksParamSet genparamSet = { .data = (uint8_t *)hksParamSet, .dataLen = hksParamSet->paramSetSize };
    uint8_t outKeyBuffer[512];
    struct HuksBlob outKey = { .data = outKeyBuffer, .dataLen = sizeof(outKeyBuffer) };
    ret = g_huksHdiProxy->GenerateKey(g_huksHdiProxy, &keyAlias, &genparamSet, &key, &outKey);
    HksHdiFreeParamSet(&hksParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HksParamSet *initParamSet = nullptr;
    ret = HksHdiBuildParamSetWithParams(&initParamSet, g_aes128GcmInitParams,
        sizeof(g_aes128GcmInitParams) / sizeof(g_aes128GcmInitParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HuksParamSet paramSet = { .data = (uint8_t *)initParamSet, .dataLen = initParamSet->paramSetSize };
    uint8_t outHandleBuffer[12];
    struct HuksBlob outHandle = { .data = outHandleBuffer, .dataLen = sizeof(outHandleBuffer) };
    uint8_t outHandleToken[32];
    struct HuksBlob outToken = { .data = outHandleToken, .dataLen = sizeof(outHandleToken) };
    ret = g_huksHdiProxy->Init(g_huksHdiProxy, &outKey, &paramSet, &outHandle, &outToken);
    HksHdiFreeParamSet(&initParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);
    ASSERT_EQ(outHandle.dataLen, 8);
}

/**
 * @tc.name: HuksHdiApiTest.MultiThreadTest001
 * @tc.desc: Test init key with current software huks driver(hardcoded root key) in multi thread scenario;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWMTEST_F(HuksHdiApiTest, MultiThreadTest001, TestSize.Level0, 10)
{
    std::thread::id thisId = std::this_thread::get_id();
    std::ostringstream oss;
    oss << thisId;
    std::string thisIdString = oss.str();
    long int thread_id = atol(thisIdString.c_str());
    HUKS_TEST_LOG_I("running thread id:%ld start\n", thread_id);

    ASSERT_NE(g_huksHdiProxy, nullptr);
    ASSERT_NE(g_huksHdiProxy->Init, nullptr);
    struct HksParamSet *hksParamSet = nullptr;
    uint8_t keyBuff[1] = {0};
    static struct HuksBlob key = { .data = keyBuff, .dataLen = sizeof(keyBuff) };
    struct HuksBlob keyAlias = { .data = (uint8_t *)GENERATE_KEY_ALIAS, .dataLen = sizeof(GENERATE_KEY_ALIAS) };

    int ret = HksHdiBuildParamSetWithParams(&hksParamSet, g_aes128GcmGenImportParams,
        sizeof(g_aes128GcmGenImportParams) / sizeof(g_aes128GcmGenImportParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HuksParamSet genparamSet = { .data = (uint8_t *)hksParamSet, .dataLen = hksParamSet->paramSetSize };
    uint8_t outKeyBuffer[512];
    struct HuksBlob outKey = { .data = outKeyBuffer, .dataLen = sizeof(outKeyBuffer) };
    ret = g_huksHdiProxy->GenerateKey(g_huksHdiProxy, &keyAlias, &genparamSet, &key, &outKey);
    HksHdiFreeParamSet(&hksParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HksParamSet *initParamSet = nullptr;
    ret = HksHdiBuildParamSetWithParams(&initParamSet, g_aes128GcmInitParams,
        sizeof(g_aes128GcmInitParams) / sizeof(g_aes128GcmInitParams[0]));
    ASSERT_EQ(ret, HUKS_SUCCESS);

    struct HuksParamSet paramSet = { .data = (uint8_t *)initParamSet, .dataLen = initParamSet->paramSetSize };
    uint8_t outHandleBuffer[12];
    struct HuksBlob outHandle = { .data = outHandleBuffer,  .dataLen = sizeof(outHandleBuffer) };
    uint8_t outHandleToken[32];
    struct HuksBlob outToken = { .data = outHandleToken, .dataLen = sizeof(outHandleToken) };
    ret = g_huksHdiProxy->Init(g_huksHdiProxy, &outKey, &paramSet, &outHandle, &outToken);
    HksHdiFreeParamSet(&initParamSet);
    ASSERT_EQ(ret, HUKS_SUCCESS);
    ASSERT_EQ(outHandle.dataLen, 8);
    HUKS_TEST_LOG_I("running thread id:%ld end\n", thread_id);
}
}
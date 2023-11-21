/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "v1_0/media_decrypt_module_service.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "session.h"
#include "ashmem.h"

#define HDF_LOG_TAG    media_decrypt_module_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
static const size_t blockSize = AES_BLOCK_SIZE;
static const size_t blockBitSize = blockSize * 8;

MediaDecryptModuleService::MediaDecryptModuleService(sptr<Session>& session)
{
    HDF_LOGI("%{public}s: start", __func__);
    session_ = session;
    HDF_LOGI("%{public}s: end", __func__);
}

// int32_t MediaDecryptModuleService::RequiresSecureDecoderModule(const std::string& mimeType, bool& required)
// {
//     HDF_LOGI("%{public}s: start", __func__);
//     required = false;
//     HDF_LOGI("%{public}s: end", __func__);
//     return HDF_SUCCESS;
// }

int32_t MediaDecryptModuleService::DecryptMediaData(bool secure, const CryptoInfo& cryptoInfo,
     const DrmBuffer& srcBuffer, const DrmBuffer& destBuffer)
{
    HDF_LOGI("%{public}s: start", __func__);
    ++decryptNumber;
    int32_t ret = HDF_FAILURE;
    if (session_ == nullptr) {
        ++errorDecryptNumber;
        (void)::close(srcBuffer.fd);
        (void)::close(destBuffer.fd);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> key;
    ret = session_->getKeyValueByKeyId(cryptoInfo.keyId, key);
    if (ret != HDF_SUCCESS) {
        HDF_LOGI("%{public}s: could not find key", __func__);
    }

    uint8_t *srcData = nullptr;
    uint8_t *destData = nullptr;
    size_t data_size = 0;
    for (auto &subSample : cryptoInfo.subSamples) {
        if (subSample.clearHeaderLen > 0) {
            data_size += subSample.clearHeaderLen;
        }

        if (subSample.payLoadLen > 0) {
            data_size += subSample.payLoadLen;
        }
    }

    srcData = (uint8_t *)mmap(nullptr, data_size, PROT_READ | PROT_WRITE, MAP_SHARED, srcBuffer.fd, 0);
    if (srcData == nullptr) {
        HDF_LOGE("%{public}s: invalid src_shared_mem", __func__);
        ++errorDecryptNumber;
        (void)::close(srcBuffer.fd);
        (void)::close(destBuffer.fd);
        return HDF_FAILURE;
    }

    destData = (uint8_t *)mmap(nullptr, data_size, PROT_READ | PROT_WRITE, MAP_SHARED, destBuffer.fd, 0);
    if (destData == nullptr) {
        HDF_LOGE("%{public}s: invalid dest_shared_mem", __func__);
        (void)munmap(srcData, data_size);
        ++errorDecryptNumber;
        (void)::close(srcBuffer.fd);
        (void)::close(destBuffer.fd);
        return HDF_FAILURE;
    }

    switch (cryptoInfo.type) {
        case ALGTYPE_UNENCRYPTED:
            ret = CopyBuffer(srcData, destData, cryptoInfo.subSamples);
            break;
        case ALGTYPE_AES_WV:
            ret = DecryptByAesCbc(key, cryptoInfo.iv, srcData, destData, cryptoInfo.subSamples);
            break;
        case ALGTYPE_AES_CBC:
            ret = DecryptByAesCbc(key, cryptoInfo.iv, srcData, destData, cryptoInfo.subSamples);
            break;
        case ALGTYPE_AES_CTR:
        case ALGTYPE_SM4_CBC:
            ret = DecryptBySM4Cbc(key, cryptoInfo.iv, srcData, destData, cryptoInfo.subSamples);
            break;
        default:
            (void)munmap(srcData, data_size);
            (void)munmap(destData, data_size);
            (void)::close(srcBuffer.fd);
            (void)::close(destBuffer.fd);
            HDF_LOGE("CryptoAlgorithmType is not supported");
            ++errorDecryptNumber;
            return HDF_ERR_INVALID_PARAM;
    }
    (void)munmap(srcData, data_size);
    (void)munmap(destData, data_size);
    (void)::close(srcBuffer.fd);
    (void)::close(destBuffer.fd);
    if (ret != HDF_SUCCESS) {
        ++errorDecryptNumber;
        return ret;
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaDecryptModuleService::DecryptBySM4Cbc(const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv, uint8_t* srcData, uint8_t* destData,
    const std::vector<SubSample>& subSamples)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (key.size() != blockSize || iv.size() != blockSize) {
        HDF_LOGE("key or iv length error");
        return HDF_ERR_INVALID_PARAM;
    }

    EVP_CIPHER_CTX *ctx;
    size_t offset = 0;
    int len;

    HDF_LOGI("%{public}s: before EVP_DecryptInit_ex", __func__);
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), nullptr, key.data(), iv.data());
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    HDF_LOGI("%{public}s: after EVP_DecryptInit_ex", __func__);

    for (auto &subSample:subSamples) {
        if (subSample.clearHeaderLen > 0) {
            HDF_LOGI("%{public}s: before clear header memcpy", __func__);
            memcpy(destData + offset, srcData + offset, subSample.clearHeaderLen);
            HDF_LOGI("%{public}s: after clear header memcpy", __func__);
            offset += subSample.clearHeaderLen;
        }

        if (subSample.payLoadLen > 0) {
            HDF_LOGI("%{public}s: before EVP_DecryptUpdate", __func__);
            // Decrypt data
            EVP_DecryptUpdate(ctx, (unsigned char *)(destData + offset), &len,
                (const unsigned char *)(srcData + offset), (int)(subSample.payLoadLen));
            // End decryption process
            EVP_DecryptFinal_ex(ctx, (unsigned char *)(destData + offset + len), &len);;
            HDF_LOGI("%{public}s: after EVP_DecryptFinal_ex", __func__);
            offset += subSample.payLoadLen;
        }
    }
    // release context
    EVP_CIPHER_CTX_free(ctx);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaDecryptModuleService::DecryptByAesCbc(const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv, uint8_t* srcData, uint8_t* destData,
    const std::vector<SubSample>& subSamples)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (key.size() != blockSize || iv.size() != blockSize) {
        HDF_LOGE("key or iv length error");
        return HDF_ERR_INVALID_PARAM;
    }

    size_t offset = 0;
    AES_KEY opensslKey;
    HDF_LOGI("%{public}s: before AES_set_decrypt_key", __func__);
    AES_set_decrypt_key((unsigned char*)key.data(), blockBitSize, &opensslKey);
    HDF_LOGI("%{public}s: after AES_set_decrypt_key", __func__);

    for (auto &subSample:subSamples) {
        if (subSample.clearHeaderLen > 0) {
            HDF_LOGI("%{public}s: before clear header memcpy", __func__);
            memcpy(destData + offset, srcData + offset, subSample.clearHeaderLen);
            HDF_LOGI("%{public}s: after clear header memcpy", __func__);
            offset += subSample.clearHeaderLen;
        }

        if (subSample.payLoadLen > 0) {
            HDF_LOGI("%{public}s: before AES_cbc_encrypt", __func__);
            AES_cbc_encrypt((uint8_t*)srcData + offset, (uint8_t*)destData + offset,
                    subSample.payLoadLen, &opensslKey,
                    (unsigned char *)iv.data(), AES_DECRYPT);
            HDF_LOGI("%{public}s: after AES_cbc_encrypt", __func__);
            offset += subSample.payLoadLen;
        }
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaDecryptModuleService::CopyBuffer(uint8_t* srcBuffer, uint8_t* destBuffer,
    const std::vector<SubSample>& subSamples)
{
    HDF_LOGI("%{public}s: start", __func__);
    size_t offset = 0;
    for (auto &subSample:subSamples) {
        if (subSample.clearHeaderLen > 0) {
            memcpy(destBuffer + offset, srcBuffer + offset,
                    subSample.clearHeaderLen);
            offset += subSample.clearHeaderLen;
        }

        if (subSample.payLoadLen > 0) {
            memcpy(destBuffer + offset, srcBuffer + offset,
                    subSample.payLoadLen);
            offset += subSample.payLoadLen;
        }
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaDecryptModuleService::GetDecryptNumber()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return decryptNumber;
}

int32_t MediaDecryptModuleService::GetErrorDecryptNumber()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return errorDecryptNumber;
}

int32_t MediaDecryptModuleService::Release()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

} // V1_0
} // Drm
} // HDI
} // OHOS

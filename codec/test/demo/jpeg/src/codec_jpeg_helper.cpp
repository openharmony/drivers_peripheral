/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_jpeg_helper.h"
#include <ashmem.h>
#include <cerrno>
#include <cstring>
#include <securec.h>
#include "hdf_log.h"

static int8_t UnZigZagTable[64] = {
    0,  1,  5,  6, 14, 15, 27, 28,
    2,  4,  7, 13, 16, 26, 29, 42,
    3,  8, 12, 17, 25, 30, 41, 43,
    9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63};

using namespace OHOS::HDI::Codec::Image::V2_0;
int32_t CodecJpegHelper::JpegAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t fd)
{
    HDF_LOGI("enter");
    int32_t curPos = 0;
    // SOI
    curPos = PutInt16(buffer, curPos, 0xffd8);
    if (curPos < 0) {
        HDF_LOGE("assemble SOI error");
        return -1;
    }

    // DQT
    curPos = JpegDqtAssemble(decInfo, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble DQT error");
        return -1;
    }

    // DHT
    curPos = JpegDhtAssemble(decInfo, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble DHT error");
        return -1;
    }
    // DRI
    curPos = JpegDriAssemble(decInfo, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble DRI error");
        return -1;
    }

    // SOF
    curPos = JpegSofAssemble(decInfo, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF error");
        return -1;
    }
    // SOS
    curPos = JpegSosAssemble(decInfo, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble SOS error");
        return -1;
    }
    // DATA
    curPos = JpegDataAssemble(buffer, curPos, fd);
    if (curPos < 0) {
        HDF_LOGE("assemble CompressedData error");
        return -1;
    }
    // EOI
    curPos = PutInt16(buffer, curPos, 0xffd9);
    if (curPos < 0) {
        HDF_LOGE("assemble EOI error");
        return -1;
    }
    return curPos;
}

bool CodecJpegHelper::DessambleJpeg(int8_t *buffer, size_t bufferLen, struct CodecJpegDecInfo &decInfo,
                                    std::unique_ptr<int8_t[]> &compressBuffer, uint32_t &comBufLen, uint32_t &dataStart)
{
    HDF_LOGI("enter");
    int8_t *start = buffer;
    const int8_t *end = buffer + bufferLen;
    while (start < end) {
        JpegMarker marker = (JpegMarker)FindMarker(start);
        start += 2;  // 2: marker len
        switch (marker) {
            case SOI:
            case EOI:
                break;
            case SOF0:
                start += DessambleSof(start, decInfo);
                break;
            case DHT:
                start += DessambleDht(start, decInfo);
                break;
            case SOS: {
                start += DessambleSos(start, decInfo);
                dataStart = start - buffer;
                // compressed data start
                auto len = DessambleCompressData(start, compressBuffer, comBufLen);
                if (len < 0) {
                    HDF_LOGE("copy compressed data error");
                    return false;
                }
                start += len;
                break;
            }

            case DQT:
                start += DessambleDqt(start, decInfo);
                break;
            case DRI: {
                start += 2;  // 2: marker len
                decInfo.restartInterval = GetInt16(start);
                start += 2;  // 2: interval len
                break;
            }
            default: {
                short len = GetInt16(start);
                start += len;
                HDF_LOGW("skip marker[%{public}x], len[%{public}d]", marker, len);
                break;
            }
        }
    }
    return true;
}
int32_t CodecJpegHelper::JpegDqtAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    // flag
    curPos = PutInt16(buffer, curPos, 0xffdb);
    if (curPos < 0) {
        HDF_LOGE("assemble DQT flag error");
        return curPos;
    }

    // skip len first
    int32_t lenPos = curPos;
    curPos += 2;  // 2: marker len

    // data
    for (size_t i = 0; i < decInfo.quantTbl.size(); i++) {
        if (!decInfo.quantTbl[i].tableFlag) {
            break;
        }
        uint8_t index = 0;         // precision 1:16bit, 0： 8bit, deault:1
        index = (index << 4) | i;  // precision << 4 | tableid
        curPos = PutInt8(buffer, curPos, index);
        if (curPos < 0) {
            HDF_LOGE("assemble precision and tableid error");
            return curPos;
        }

        for (size_t j = 0; j < decInfo.quantTbl[i].quantVal.size(); j++) {
            HDF_LOGI("decInfo.quantTbl[%{public}zu].quantVal[%{public}zu] = %{public}d", i, j,
                decInfo.quantTbl[i].quantVal[j]);
            curPos = PutInt16(buffer, curPos, decInfo.quantTbl[i].quantVal[j]);
        }
    }
    int16_t bufferLen = static_cast<int16_t>(curPos - lenPos);
    auto ret = PutInt16(buffer, lenPos, bufferLen);
    if (ret < 0) {
        HDF_LOGE("assemble len error");
        return ret;
    }
    return curPos;
}
int32_t CodecJpegHelper::JpegDriAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos)
{
    HDF_LOGI("enter, restartInterval = %{public}d curPos = %{public}d", decInfo.restartInterval, curPos);
    if (decInfo.restartInterval <= 0) {
        return curPos;
    }
    curPos = PutInt16(buffer, curPos, 0xffdd);
    if (curPos < 0) {
        HDF_LOGE("assemble DRI flag error");
        return curPos;
    }

    curPos = PutInt16(buffer, curPos, 4);  // 4: dri data len( marker len included)
    if (curPos < 0) {
        HDF_LOGE("assemble DRI len error");
        return curPos;
    }

    curPos = PutInt16(buffer, curPos, decInfo.restartInterval);
    if (curPos < 0) {
        HDF_LOGE("assemble dri value error");
        return curPos;
    }
    return curPos;
}
int32_t CodecJpegHelper::JpegDhtAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    curPos = JpegDhtAssemble(decInfo.dcHuffTbl, buffer, curPos);
    if (curPos < 0) {
        HDF_LOGE("assemble dc hufman error");
        return curPos;
    }

    curPos = JpegDhtAssemble(decInfo.acHuffTbl, buffer, curPos, false);
    if (curPos < 0) {
        HDF_LOGE("assemble ac hufman error");
    }
    return curPos;
}
int32_t CodecJpegHelper::JpegDhtAssemble(const std::vector<CodecJpegHuffTable> &table, int8_t *buffer, int32_t curPos,
                                         bool dc)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    // DC Hufman
    curPos = PutInt16(buffer, curPos, 0xffc4);
    if (curPos < 0) {
        HDF_LOGE("assemble hufman flag error");
        return curPos;
    }
    // skip len
    int32_t lenPos = curPos;
    curPos += 2;  // 2: marker len
    for (size_t i = 0; i < table.size(); i++) {
        if (!table[i].tableFlag) {
            break;
        }
        uint8_t type = 0;  // type  0:DC, 1:AC
        if (!dc) {
            type = 1;
        }
        type = (type << 4) | i;  // type << 4 | tableid
        curPos = PutInt8(buffer, curPos, type);
        if (curPos < 0) {
            HDF_LOGE("assemble tableid and dc/ac error");
            return curPos;
        }
        // bits
        auto ret = memcpy_s(buffer + curPos, table[i].bits.size(), table[i].bits.data(), table[i].bits.size());
        if (ret != EOK) {
            char buf[MAX_BUFFER_LEN] = {0};
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("assemble bits error ret = %{public}s", buf);
            return ret;
        }
        curPos += table[i].bits.size();
        // val
        ret = memcpy_s(buffer + curPos, table[i].huffVal.size(), table[i].huffVal.data(), table[i].huffVal.size());
        if (ret != EOK) {
            HDF_LOGE("assemble huffVal error, ret = %{public}d", ret);
            return ret;
        }
        curPos += table[i].huffVal.size();
    }
    int16_t bufferLen = static_cast<int16_t>(curPos - lenPos);
    auto ret = PutInt16(buffer, lenPos, bufferLen);
    if (ret < 0) {
        HDF_LOGE("assemble len error");
        return ret;
    }
    return curPos;
}

int32_t CodecJpegHelper::JpegSofAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    // flag
    curPos = PutInt16(buffer, curPos, 0xffc0);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF flag error");
        return curPos;
    }

    int16_t len = decInfo.numComponents * 3 + 8; // * rgb channel + other data
    curPos = PutInt16(buffer, curPos, len);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF len error");
        return curPos;
    }

    int8_t precision = decInfo.dataPrecision & 0xFF;
    curPos = PutInt8(buffer, curPos, precision);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF precision error");
        return curPos;
    }

    // width
    int16_t width = decInfo.imageHeight & 0xFFFF;
    curPos = PutInt16(buffer, curPos, width);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF width error");
        return curPos;
    }

    //  height
    int16_t height = decInfo.imageWidth & 0xFFFF;
    curPos = PutInt16(buffer, curPos, height);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF width error");
        return curPos;
    }
    // components
    int8_t components = decInfo.numComponents & 0xFF;
    curPos = PutInt8(buffer, curPos, components);
    if (curPos < 0) {
        HDF_LOGE("assemble SOF components error");
        return curPos;
    }
    for (size_t i = 0; i < decInfo.compInfo.size(); i++) {
        int8_t componentId = decInfo.compInfo[i].componentId;
        // byte offset
        int8_t sampFactor = ((decInfo.compInfo[i].hSampFactor & 0xFF) << 4) | (decInfo.compInfo[i].vSampFactor & 0xFF);
        int8_t quantity = decInfo.compInfo[i].quantTableNo;
        int8_t bufferValue[] = {componentId, sampFactor, quantity};
        auto ret = memcpy_s(buffer + curPos, sizeof(bufferValue), bufferValue, sizeof(bufferValue));
        if (ret != EOK) {
            HDF_LOGE("assemble component error, ret = %{public}d", ret);
            return ret;
        }
        curPos += sizeof(bufferValue);
    }
    return curPos;
}
int32_t CodecJpegHelper::JpegSosAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    // flag
    curPos = PutInt16(buffer, curPos, 0xffda);
    if (curPos < 0) {
        HDF_LOGE("assemble SOS flag error");
        return curPos;
    }

    int16_t len = decInfo.numComponents * 2 + 6; // * rgb table length + other data
    curPos = PutInt16(buffer, curPos, len);
    if (curPos < 0) {
        HDF_LOGE("assemble SOS len error");
        return curPos;
    }

    int8_t components = decInfo.numComponents & 0xFF;
    curPos = PutInt8(buffer, curPos, components);
    if (curPos < 0) {
        HDF_LOGE("assemble SOS components error");
        return curPos;
    }

    for (size_t i = 0; i < decInfo.compInfo.size(); i++) {
        int8_t componentId = decInfo.compInfo[i].componentId;
        int8_t indexNo = ((decInfo.compInfo[i].dcTableNo & 0xFF) << 4) | (decInfo.compInfo[i].acTableNo & 0xFF);
        int16_t value = ((componentId << 8) | indexNo) & 0xffff;
        curPos = PutInt16(buffer, curPos, value);
        if (curPos < 0) {
            HDF_LOGE("assemble SOS component value error");
            return curPos;
        }
    }
    int8_t dataStart[] = {0x00, 0x3F, 0x00};
    auto ret = memcpy_s(buffer + curPos, sizeof(dataStart), dataStart, sizeof(dataStart));
    if (ret != EOK) {
        HDF_LOGE("assemble SOS data flag error, ret = %{public}d", ret);
        return ret;
    }
    curPos += sizeof(dataStart);
    return curPos;
}
int32_t CodecJpegHelper::JpegDataAssemble(int8_t *buffer, int32_t curPos, int32_t fd)
{
    HDF_LOGI("enter. curPos = %{public}d", curPos);
    int32_t size = OHOS::AshmemGetSize(fd);
    HDF_LOGI("get size %{public}d from fd %{public}d", size, fd);
    OHOS::Ashmem mem(fd, size);
    // check ret value
    mem.MapReadOnlyAshmem();
    auto addr = const_cast<void *>(mem.ReadFromAshmem(0, 0));
    auto ret = memcpy_s(buffer + curPos, size, addr, size);
    if (ret != EOK) {
        HDF_LOGE("assemble compressed data error, ret = %{public}d", ret);
        mem.UnmapAshmem();
        if (ret > 0) {
            return -ret;
        }
        return ret;
    }
    mem.UnmapAshmem();
    mem.CloseAshmem();
    curPos += size;
    return curPos;
}

int32_t CodecJpegHelper::DessambleSof(int8_t *buffer, struct CodecJpegDecInfo &decInfo)
{
    HDF_LOGI("dessamble SOI");
    // len
    int32_t len = GetInt16(buffer);
    buffer += 2;  // 2: marker len
    // precision
    decInfo.dataPrecision = GetInt8(buffer);
    buffer++;
    // height
    decInfo.imageHeight = GetInt16(buffer);
    buffer += 2;  // 2: height len
    // width
    decInfo.imageWidth = GetInt16(buffer);
    buffer += 2;  // 2: width len

    decInfo.numComponents = GetInt8(buffer);
    buffer++;

    HDF_LOGI("image width[%{public}d],height[%{public}d],components[%{public}d]", decInfo.imageWidth,
        decInfo.imageHeight, decInfo.numComponents);
    for (size_t i = 0; i < decInfo.numComponents; i++) {
        CodecJpegCompInfo comInfo;

        comInfo.infoFlag = true;
        comInfo.componentId = GetInt8(buffer);
        buffer++;

        int8_t sampFactor = GetInt8(buffer);
        buffer++;
        comInfo.hSampFactor = (sampFactor >> 4) & 0xFF;  // 4: hsampfactor offset
        comInfo.vSampFactor = sampFactor & 0x0F;

        comInfo.quantTableNo = GetInt8(buffer);
        buffer++;
        decInfo.compInfo.push_back(std::move(comInfo));
        HDF_LOGI("componentId[%{public}d],hSampFactor[%{public}d],vSampFactor[%{public}d],quantTableNo[%{public}d]",
            comInfo.componentId, comInfo.hSampFactor, comInfo.vSampFactor, comInfo.quantTableNo);
    }
    return len;
}
int32_t CodecJpegHelper::DessambleSos(int8_t *buffer, struct CodecJpegDecInfo &decInfo)
{
    HDF_LOGI("dessamble SOS");
    int32_t len = GetInt16(buffer);
    buffer += 2;  // 2:marker len

    int32_t components = GetInt8(buffer);
    buffer++;

    for (int32_t i = 0; i < components; i++) {
        decInfo.compInfo[i].infoFlag = true;

        int32_t componentId = GetInt8(buffer);
        (void)componentId;
        buffer++;
        // index not used
        auto data = GetInt8(buffer);
        buffer++;
        decInfo.compInfo[i].dcTableNo = (data >> 4) & 0x0F;  // 4: dctable offset
        decInfo.compInfo[i].acTableNo = data & 0x0F;
        HDF_LOGI("componentId[%{public}d],dcTableNo[%{public}d],acTableNo[%{public}d]", componentId,
            decInfo.compInfo[i].dcTableNo, decInfo.compInfo[i].acTableNo);
    }
    buffer += 3;  // skip 0x003F00
    return len;
}
int32_t CodecJpegHelper::DessambleCompressData(int8_t *buffer, std::unique_ptr<int8_t[]> &compressBuffer,
                                               uint32_t &comBufLen)
{
    int8_t *dataStart = buffer;
    do {
        int32_t v = GetInt8(buffer);
        buffer++;
        if (v != 0xff) {
            continue;
        }
        v = GetInt8(buffer);
        buffer++;
        if (v != 0xd9) {
            continue;
        }
        buffer -= 2;  // 2: marker len
        break;
    } while (1);
    comBufLen = (int32_t)(buffer - dataStart) + 1;
    compressBuffer = std::make_unique<int8_t[]>(comBufLen);
    auto ret = memcpy_s(compressBuffer.get(), comBufLen, dataStart, comBufLen);
    if (ret != EOK) {
        HDF_LOGE("copy compressed data error, dataLen %{public}d, ret %{public}d", comBufLen, ret);
        compressBuffer = nullptr;
        return ret;
    }
    return comBufLen;
}
int32_t CodecJpegHelper::DessambleDqt(int8_t *buffer, struct CodecJpegDecInfo &decInfo)
{
    HDF_LOGI("dessamble DQT");
    int8_t *bufferOri = buffer;
    int32_t len = GetInt16(buffer);
    buffer += 2;  // 2: marker len
    // maybe has more dqt table
    while ((buffer - bufferOri) < len) {
        auto data = GetInt8(buffer);
        buffer++;
        int32_t tableId = data & 0x000f;
        (void)tableId;
        int32_t size = 64;
        CodecJpegQuantTable table;
        table.tableFlag = true;
        table.quantVal.resize(size);
        std::vector<uint16_t> mtx;
        HDF_LOGI("tableid[%{public}d]", tableId);
        for (int32_t i = 0; i < size; i++) {
            if (((data >> 4) & 0x0f) == 1) { // 4: low 4 bits, 1: for 16 bits
                mtx.push_back(static_cast<int16_t>(GetInt16(buffer)));
                buffer += 2;  // 2: data offset
            } else {
                mtx.push_back(static_cast<int8_t>(GetInt8(buffer)));
                buffer += 1;  // 1: data offset
            }
        }
        // unzigzag quant table
        for (int32_t i = 0; i < size; i++) {
            table.quantVal[i] = mtx[UnZigZagTable[i]];
        }
        decInfo.quantTbl.push_back(std::move(table));
    }
    return len;
}
int32_t CodecJpegHelper::DessambleDht(int8_t *buffer, struct CodecJpegDecInfo &decInfo)
{
    HDF_LOGI("dessamble DHT");
    int8_t *bufferOri = buffer;
    int32_t len = GetInt16(buffer);
    buffer += 2;  // 2: marker len
    // 可能存在多个表在同一个dht marker 中
    while ((buffer - bufferOri) < len) {
        auto data = GetInt8(buffer);
        buffer++;
        int32_t tableId = data & 0x000f;
        (void)tableId;
        int32_t acOrDc = (data >> 4) & 0x0f;  // 0:DC, 1:AC, 4: ac/dc data offset
        CodecJpegHuffTable table;
        table.tableFlag = true;
        int32_t num = 0;
        for (size_t i = 0; i < 16; i++) {  // 16: Data size
            auto data = GetInt8(buffer);
            buffer++;
            table.bits.push_back(data);
            num += data & 0x00ff;
        }
        HDF_LOGI("tableid[%{public}d], acOrDc[%{public}d], num[%{public}d]", tableId, acOrDc, num);
        // val
        for (int32_t i = 0; i < num; i++) {
            table.huffVal.push_back(*buffer++);
        }
        if (acOrDc == 1) {
            decInfo.acHuffTbl.push_back(std::move(table));
        } else {
            decInfo.dcHuffTbl.push_back(std::move(table));
        }
    }
    return len;
}

int32_t CodecJpegHelper::FindMarker(int8_t *start)
{
    int32_t marker = GetInt16(start);
    return marker;
}

int32_t CodecJpegHelper::PutInt16(int8_t *buffer, int32_t curPos, int16_t value)
{
    int8_t data[] = {value >> 8, value & 0xFF};
    auto ret = memcpy_s(buffer + curPos, sizeof(data), data, sizeof(data));
    if (ret != EOK) {
        HDF_LOGE("memcpy ret err %{public}d", ret);
        return -1;
    }
    return curPos + sizeof(data);
}

int32_t CodecJpegHelper::PutInt8(int8_t *buffer, int32_t curPos, int8_t value)
{
    auto ret = memcpy_s(buffer + curPos, sizeof(value), &value, sizeof(value));
    if (ret != EOK) {
        HDF_LOGE("memcpy ret err %{public}d", ret);
        return -1;
    }
    return curPos + sizeof(value);
}

int32_t CodecJpegHelper::GetInt8(int8_t *buffer)
{
    return buffer[0] & 0x00ff;
}

int32_t CodecJpegHelper::GetInt16(int8_t *buffer)
{
    return ((buffer[0] << 8) & 0x00ff00) | (buffer[1] & 0x00ff);  // 8:data offset
}

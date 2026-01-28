
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ai hold posture adapter process.
 * Create: 2025-02-06
 */
#include "sensor_sdc_adapter.h"
#include "sensor_sdc_service.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <cerrno>
#include <unistd.h>

namespace OHOS {
namespace Telephony {

static const std::string SIGNAL_HUB_DEV_PATH = "/dev/signal_hub";
static constexpr int MMAP_PAGE_SIZE = 4 * 1024;
static constexpr int MMAP_BUF_SIZE = 256 * MMAP_PAGE_SIZE;
static constexpr int MMAP_OFFSET = 0;
static constexpr int SENSOR_SAMPLE_RATE_HZ = 100;
static constexpr int MAX_ADDR_OFFSET = 974848;  // 当前sensor sdc共享内存最大的偏移量

SignalAIAdapter::~SignalAIAdapter()
{
    ReleaseSensors();
    CloseSignalHubDevice();
}

int SignalAIAdapter::GetAccAddrOffset()
{
    return accAddrOffset_;
}

int SignalAIAdapter::GetGyrAddrOffset()
{
    return gyrAddrOffset_;
}

uint8_t *SignalAIAdapter::GetSensorShareAddr()
{
    return sensorShareAddr_;
}

bool SignalAIAdapter::OpenSignalHubDevice()
{
    printf("SIGNALAI:Adapter:OpenSignalHubDevice start");
    if (signalHubDeviceFd_ >= 0) {
        printf("SIGNALAI:Adapter:OpenSignalHubDevice device already opened");
        return true;
    }

    signalHubDeviceFd_ = open(SIGNAL_HUB_DEV_PATH.c_str(), O_RDWR);
    if (signalHubDeviceFd_ < 0) {
        printf("SIGNALAI:Adapter:OpenSignalHubDevice failed ret = %s", strerror(errno));
        return false;
    }
    return SignalHubDeviceMmap();
}

bool SignalAIAdapter::SignalHubDeviceMmap()
{
    if (sensorShareAddr_ == nullptr && signalHubDeviceFd_ >= 0) {
        sensorShareAddr_ = reinterpret_cast<uint8_t*>(mmap(nullptr, MMAP_BUF_SIZE, PROT_READ, MAP_SHARED,
            signalHubDeviceFd_, MMAP_OFFSET));
        if (sensorShareAddr_ == nullptr || sensorShareAddr_ == reinterpret_cast<uint8_t*>(UINT8_MAX)) {
            printf("SIGNALAI:Adapter:OpenSignalHubDevice mmap fail ret = %s", strerror(errno));
            CloseSignalHubDevice();
            return false;
        }
        printf("SIGNALAI:Adapter:OpenSignalHubDevice mmap sensorShareAddr_ success");
    }
    return true;
}

void SignalAIAdapter::SignalHubDeviceMunmap()
{
    if (sensorShareAddr_ != nullptr) {
        munmap(sensorShareAddr_, MMAP_BUF_SIZE);
    }
}

void SignalAIAdapter::CloseSignalHubDevice()
{
    if (signalHubDeviceFd_ >= 0) {
        SignalHubDeviceMunmap();
        close(signalHubDeviceFd_);
        signalHubDeviceFd_ = -1;
        sensorShareAddr_ = nullptr;
    }
}

bool SignalAIAdapter::InitSensors()
{
    sensorInterface_ = HDI::Sensor::V3_0::ISensorInterface::Get();
    if (sensorInterface_ == nullptr) {
        printf("SIGNALAI:Adapter:sensorInterface_ fail");
        return false;
    }
    std::vector<OHOS::HDI::Sensor::V3_0::SdcSensorInfo> sdcSensorInfo;
    auto ret = sensorInterface_->GetSdcSensorInfo(sdcSensorInfo);
    if (ret != 0) {
        printf("SIGNALAI:Adapter:GetSdcSensorInfo fail ret = %d.", ret);
        return false;
    }
    for (const auto& it : sdcSensorInfo) {
        printf(
            "SIGNALAI:Adapter:SdcSensorInfo offset=%ld, sensorId=%d, ddrSize=%d,",
            it.offset, it.deviceSensorInfo.sensorType, it.ddrSize);
        if (it.deviceSensorInfo.sensorType == HDI::Sensor::V3_0::HDF_SENSOR_TYPE_ACCELEROMETER) {
            if (it.ddrSize <= SDC_HEADER_SIZE) {
                printf("SIGNALAI:Adapter: acc ddr size %d not good", it.ddrSize);
                return false;
            }
            accAddrOffset_ = it.offset;
            accMaxFifoCount_ = (it.ddrSize - SDC_HEADER_SIZE) / SDC_VEC3_SIZE;
            accSensorInfo_ = it.deviceSensorInfo;
            printf("SIGNALAI:Adapter:SdcSensorInfo acc offset=%d, maxFifoCount=%d",
                accAddrOffset_, accMaxFifoCount_);
            continue;
        }
        if (it.deviceSensorInfo.sensorType == HDI::Sensor::V3_0::HDF_SENSOR_TYPE_GYROSCOPE) {
            if (it.ddrSize <= SDC_HEADER_SIZE) {
                printf("SIGNALAI:Adapter: gyr ddr size %d not good", it.ddrSize);
                return false;
            }
            gyrAddrOffset_ = it.offset;
            gyrMaxFifoCount_ = (it.ddrSize - SDC_HEADER_SIZE) / SDC_VEC3_SIZE;
            gyrSensorInfo_ = it.deviceSensorInfo;
            printf("SIGNALAI:Adapter:SdcSensorInfo gyr offset=%d, maxFifoCount=%d",
                gyrAddrOffset_, gyrMaxFifoCount_);
            continue;
        }
    }
    return SetSdcSensors();
}

bool SignalAIAdapter::SetSdcSensors()
{
    if (accAddrOffset_ < 0 || gyrAddrOffset_ < 0 || accAddrOffset_ > MAX_ADDR_OFFSET ||
        gyrAddrOffset_ > MAX_ADDR_OFFSET) {
        printf("SIGNALAI:Adapter:get sensor offset error acc =  %d, gyr =  %d",
            accAddrOffset_, gyrAddrOffset_);
        return false;
    }

    if (!accSensorOn_) {
        printf("SIGNALAI:Adapter:SetSdcSensor ACC start.");
        auto ret = sensorInterface_->SetSdcSensor(accSensorInfo_, true, SENSOR_SAMPLE_RATE_HZ);
        if (ret != 0) {
            printf("SIGNALAI:Adapter:SetSdcSensor open ACC fail ret = %d.", ret);
            return false;
        }
        accSensorOn_ = true;
    }
    if (!gyrSensorOn_) {
        printf("SIGNALAI:Adapter:SetSdcSensor GYR start.");
        auto ret = sensorInterface_->SetSdcSensor(gyrSensorInfo_, true, SENSOR_SAMPLE_RATE_HZ);
        if (ret != 0) {
            printf("SIGNALAI:Adapter:SetSdcSensor open GYR fail ret = %d.", ret);
            return false;
        }
        gyrSensorOn_ = true;
    }
    return true;
}

void SignalAIAdapter::ReleaseSensors()
{
    accAddrOffset_ = -1;
    gyrAddrOffset_ = -1;
    if (sensorInterface_ == nullptr) {
        printf("SIGNALAI:Adapter:sensorInterface_ is null not need release");
        return;
    }
    if (accSensorOn_) {
        auto ret = sensorInterface_->SetSdcSensor(accSensorInfo_, false, SENSOR_SAMPLE_RATE_HZ);
        if (ret != 0) {
            printf("SIGNALAI:Adapter:SetSdcSensor close ACC fail ret = %d.", ret);
        }
        accSensorOn_ = false;
    }
    if (gyrSensorOn_) {
        auto ret = sensorInterface_->SetSdcSensor(gyrSensorInfo_, false, SENSOR_SAMPLE_RATE_HZ);
        if (ret != 0) {
            printf("SIGNALAI:Adapter:SetSdcSensor close GYR fail ret = %d.", ret);
        }
        gyrSensorOn_ = false;
    }
    sensorInterface_ = nullptr;
}

bool SignalAIAdapter::GetSdcFifoWriteIdx(unsigned int& accFifoWriteIdx, unsigned int& gyrFifoWriteIdx,
    unsigned int& accFifoCount, unsigned int& gyrFifoCount)
{
    if (sensorShareAddr_ == nullptr) {
        return false;
    }
    SdcDataHeader *accHeader = reinterpret_cast<SdcDataHeader*>(&sensorShareAddr_[accAddrOffset_]);
    SdcDataHeader *gyrHeader = reinterpret_cast<SdcDataHeader*>(&sensorShareAddr_[gyrAddrOffset_]);

    if (accHeader->fifoCount > accMaxFifoCount_ || gyrHeader->fifoCount > gyrMaxFifoCount_ ||
        accHeader->fifoCount == 0 || gyrHeader->fifoCount == 0) {
        printf(
            "SIGNALAI:Adapter:GetSdcFifoWriteIdx fifoCount error,accfifoCount = "
            "%d,gyrfifoCount = %d", accHeader->fifoCount, gyrHeader->fifoCount);
        return false;
    }
    accFifoWriteIdx = accHeader->fifoWriteIndex;
    gyrFifoWriteIdx = gyrHeader->fifoWriteIndex;
    accFifoCount = accHeader->fifoCount;
    gyrFifoCount = gyrHeader->fifoCount;
    return true;
}

}  // namespace Telephony
}  // namespace OHOS
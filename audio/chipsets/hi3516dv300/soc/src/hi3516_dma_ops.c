/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */
#include "audio_platform_if.h"
#ifdef __LITEOS__
#include <los_vm_iomap.h>
#else
#include <linux/dma-mapping.h>
#endif
#include "audio_sapm.h"
#include "hi3516_aiao_impl.h"
#include "audio_stream_dispatch.h"
#include "audio_driver_log.h"

#define HDF_LOG_TAG hi3516_platform_ops
const int AUDIO_CACHE_ALIGN_SIZE = 64;

#ifndef __LITEOS__
static struct device g_renderDev = {0};
static struct device g_captureDev = {0};
#endif


int32_t AudioDmaDeviceInit(const struct AudioCard *card, const struct PlatformDevice *platformDevice)
{
    const unsigned int chnId = 0;

    if (card == NULL || platformDevice == NULL || platformDevice->devData == NULL) {
        AUDIO_DRIVER_LOG_ERR("platformDevice is NULL.");
        return HDF_FAILURE;
    }
    if (platformDevice->devData->platformInitFlag == true) {
        AUDIO_DRIVER_LOG_DEBUG("platform init complete!");
        return HDF_SUCCESS;
    }

    if (AiaoHalSysInit() != HDF_SUCCESS) {
        AUDIO_DRIVER_LOG_ERR("AiaoHalSysInit:  fail.");
        return HDF_FAILURE;
    }

    /* PIN MUX */
    if (AiaoSysPinMux() != HDF_SUCCESS) {
        AUDIO_DRIVER_LOG_ERR("AiaoSysPinMux: fail.");
        return HDF_FAILURE;
    }

    /* CLK reset */
    if (AiaoClockReset() != HDF_SUCCESS) {
        AUDIO_DRIVER_LOG_ERR("AiaoClockReset: fail");
        return HDF_FAILURE;
    }

    /* aiao init */
    if (AiaoDeviceInit(chnId) != HDF_SUCCESS) {
        AUDIO_DRIVER_LOG_ERR("AiaoClockReset:  fail");
        return HDF_FAILURE;
    }

    platformDevice->devData->platformInitFlag = true;
    return HDF_SUCCESS;
}

int32_t Hi3516DmaBufAlloc(struct PlatformData *data, const enum AudioStreamType streamType)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (streamType == AUDIO_CAPTURE_STREAM) {
#ifdef __LITEOS__
        data->captureBufInfo.virtAddr = (uint32_t *)LOS_DmaMemAlloc(&data->captureBufInfo.phyAddr,
            data->captureBufInfo.cirBufMax, AUDIO_CACHE_ALIGN_SIZE, DMA_NOCACHE);
#else
        g_captureDev.coherent_dma_mask = 0xffffffffUL;
        data->captureBufInfo.virtAddr = dma_alloc_wc(&g_captureDev, data->captureBufInfo.cirBufMax,
            (dma_addr_t *)&data->captureBufInfo.phyAddr, GFP_DMA | GFP_KERNEL);
#endif
    } else if (streamType == AUDIO_RENDER_STREAM) {
#ifdef __LITEOS__
        data->renderBufInfo.virtAddr = (uint32_t *)LOS_DmaMemAlloc(&data->renderBufInfo.phyAddr,
            data->renderBufInfo.cirBufMax,
            AUDIO_CACHE_ALIGN_SIZE, DMA_NOCACHE);
#else
        g_renderDev.coherent_dma_mask = 0xffffffffUL;
        data->renderBufInfo.virtAddr = dma_alloc_wc(&g_renderDev, data->renderBufInfo.cirBufMax,
            (dma_addr_t *)&data->renderBufInfo.phyAddr, GFP_DMA | GFP_KERNEL);
#endif
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Hi3516DmaBufFree(struct PlatformData *data, const enum AudioStreamType streamType)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (streamType == AUDIO_CAPTURE_STREAM) {
        if (data->captureBufInfo.virtAddr != NULL) {
#ifdef __LITEOS__
            LOS_DmaMemFree(data->captureBufInfo.virtAddr);
#else
            dma_free_wc(&g_captureDev, data->captureBufInfo.cirBufMax, data->captureBufInfo.virtAddr,
                        data->captureBufInfo.phyAddr);
#endif
        }
    } else if (streamType == AUDIO_RENDER_STREAM) {
        if (data->renderBufInfo.virtAddr != NULL) {
#ifdef __LITEOS__
            LOS_DmaMemFree(data->renderBufInfo.virtAddr);
#else
            dma_free_wc(&g_renderDev, data->renderBufInfo.cirBufMax, data->renderBufInfo.virtAddr,
                        data->renderBufInfo.phyAddr);
#endif
        }
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t  Hi3516DmaRequestChannel(const struct PlatformData *data)
{
    (void)data;
    return HDF_SUCCESS;
}

int32_t Hi3516DmaConfigChannel(const struct PlatformData *data)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (data->pcmInfo.streamType == AUDIO_CAPTURE_STREAM) {
        if (AudioAiInit(data) != HDF_SUCCESS) {
            AUDIO_DRIVER_LOG_ERR("AudioAiInit: fail.");
            return HDF_FAILURE;
        }
        if (AipHalSetBuffWptr(0, 0) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        if (AipHalSetBuffRptr(0, 0) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    } else if (data->pcmInfo.streamType == AUDIO_RENDER_STREAM) {
        if (AudioAoInit(data) != HDF_SUCCESS) {
            AUDIO_DRIVER_LOG_ERR("AudioAoInit: fail.");
            return HDF_FAILURE;
        }
        if (AopHalSetBuffWptr(0, 0) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        if (AopHalSetBuffRptr(0, 0) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Hi3516DmaPrep(const struct PlatformData *data)
{
    (void)data;
    return HDF_SUCCESS;
}

int32_t Hi3516DmaSubmit(const struct PlatformData *data)
{
    (void)data;
    return HDF_SUCCESS;
}

int32_t Hi3516DmaPending(struct PlatformData *data)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (data->pcmInfo.streamType == AUDIO_CAPTURE_STREAM) {
        OsalMutexLock(&data->captureBufInfo.buffMutex);
        AipHalSetRxStart(data->captureBufInfo.chnId, HI_TRUE);
        OsalMutexUnlock(&data->captureBufInfo.buffMutex);
    } else if (data->pcmInfo.streamType == AUDIO_RENDER_STREAM) {
        AopHalDevEnable(data->renderBufInfo.chnId);
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Hi3516DmaPause(struct PlatformData *data)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (data->pcmInfo.streamType == AUDIO_CAPTURE_STREAM) {
        OsalMutexLock(&data->captureBufInfo.buffMutex);
        AipHalSetRxStart(data->captureBufInfo.chnId, HI_FALSE);
        OsalMutexUnlock(&data->captureBufInfo.buffMutex);
    } else if (data->pcmInfo.streamType == AUDIO_RENDER_STREAM) {
        OsalMutexLock(&data->renderBufInfo.buffMutex);
        AopHalSetTxStart(data->renderBufInfo.chnId, HI_FALSE);
        OsalMutexUnlock(&data->renderBufInfo.buffMutex);
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Hi3516DmaResume(const struct PlatformData *data)
{
    if (data == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (data->pcmInfo.streamType == AUDIO_CAPTURE_STREAM) {
        AipHalSetRxStart(data->captureBufInfo.chnId, HI_TRUE);
    } else if (data->pcmInfo.streamType == AUDIO_RENDER_STREAM) {
        AopHalDevEnable(data->renderBufInfo.chnId);
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is invalude.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Hi3516DmaPointer(struct PlatformData *data, uint32_t *pointer)
{
    int devId;
    uint32_t bytesOfPointer;
    uint32_t frameSize;
    uint32_t wPtr;
    uint32_t rPtr;

    if (data == NULL || pointer == NULL) {
        AUDIO_DRIVER_LOG_ERR("data is null");
        return HDF_FAILURE;
    }

    if (data->pcmInfo.streamType == AUDIO_RENDER_STREAM) {
        OsalMutexLock(&data->renderBufInfo.buffMutex);
        devId = data->renderBufInfo.chnId;
        frameSize = data->pcmInfo.frameSize;
        bytesOfPointer = AiaoHalReadReg(AiopRegCfg(AOP_BUFF_RPTR_REG, OFFSET_MULTL, devId));
        *pointer = AudioBytesToFrames(bytesOfPointer, frameSize);
        wPtr = data->renderBufInfo.wptrOffSet;
        OsalMutexUnlock(&data->renderBufInfo.buffMutex);
        if (AopHalSetBuffWptr(devId, wPtr) != HDF_SUCCESS) {
            AUDIO_DRIVER_LOG_ERR("AopHalSetBuffWptr failed.");
            return HDF_FAILURE;
        }
    } else if (data->pcmInfo.streamType == AUDIO_CAPTURE_STREAM) {
        OsalMutexLock(&data->captureBufInfo.buffMutex);
        devId = data->captureBufInfo.chnId;
        frameSize = data->pcmInfo.frameSize;
        bytesOfPointer = AiaoHalReadReg(AiopRegCfg(AIP_BUFF_WPTR_REG, OFFSET_MULTL, devId));
        *pointer = AudioBytesToFrames(bytesOfPointer, frameSize);
        rPtr = data->captureBufInfo.rptrOffSet;
        OsalMutexUnlock(&data->captureBufInfo.buffMutex);
        if (AipHalSetBuffRptr(devId, rPtr) != HDF_SUCCESS) {
            AUDIO_DRIVER_LOG_ERR("AipHalSetBuffRptr failed.");
            return HDF_FAILURE;
        }
    } else {
        AUDIO_DRIVER_LOG_ERR("stream Type is fail.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

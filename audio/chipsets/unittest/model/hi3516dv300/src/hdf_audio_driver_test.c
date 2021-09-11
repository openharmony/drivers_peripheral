/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hdf_audio_driver_test.h"
#include "hdf_log.h"
#include "hi3516_aiao_impl_test.h"
#include "hi3516_codec_impl_test.h"
#include "hi3516_codec_ops_test.h"
#include "hi3516_dai_adapter_test.h"
#include "hi3516_platform_ops_test.h"
#define HDF_LOG_TAG hdf_hi3516_audio_driver_test

static HdfTestCaseList g_hdfHi3516DirverTestCaseList[] = {
    {AUDIO_DRIVER_TESTDAIHWPARAMS, TestDaiHwParams},

    {AUDIO_DRIVER_TESTAUDIOPLATFORMDEVICEINIT, TestAudioPlatformDeviceInit},
    {AUDIO_DRIVER_TESTPLATFORMHWPARAMS, TestPlatformHwParams},
    {AUDIO_DRIVER_TESTPLATFORMRENDERPREPARE, TestPlatformRenderPrepare},
    {AUDIO_DRIVER_TESTPLATFORMCAPTUREPREPARE, TestPlatformCapturePrepare},
    {AUDIO_DRIVER_TESTPLATFORMWRITE, TestPlatformWrite},
    {AUDIO_DRIVER_TESTPLATFORMREAD, TestPlatformRead},
    {AUDIO_DRIVER_TESTPLATFORMRENDERSTART, TestPlatformRenderStart},
    {AUDIO_DRIVER_TESTPLATFORMCAPTURESTART, TestPlatformCaptureStart},
    {AUDIO_DRIVER_TESTPLATFORMREANERSTOP, TestPlatformRenderStop},
    {AUDIO_DRIVER_TESTPLATFORMCAPTUERSTOP, TestPlatformCaptureStop},
    {AUDIO_DRIVER_TESTPLATFORMCAPUTERPAUSE, TestPlatformCapturePause},
    {AUDIO_DRIVER_TESTPLAFORMRENDERPAUSE, TestPlatformRenderPause},
    {AUDIO_DRIVER_TESTPLATFORMRENDERRESUME, TestPlatformRenderResume},
    {AUDIO_DRIVER_TESTPLATFORMCAPTURERESUME, TestPlatformCaptureResume},

    {AUDIO_DRIVER_TESTCODECHALSYSINIT, TestCodecHalSysInit},
    {AUDIO_DRIVER_TESTACODECDEVICEININ, TestAcodecDeviceInit},
    {AUDIO_DRIVER_TESTACODECHALREADREG, TestAcodecHalReadReg},
    {AUDIO_DRIVER_TESTACODECHALWRITEREG, TestAcodecHalWriteReg},
    {AUDIO_DRIVER_TESTACODECSETI2S1FS, TestAcodecSetI2s1Fs},
    {AUDIO_DRIVER_TESTACODECSETI2S1DATAWIDTH, TestAcodecSetI2s1DataWidth},

    {AUDIO_DRIVER_TESTCODECDEVICEINIT, TestCodecDeviceInit},
    {AUDIO_DRIVER_TESTCODECDAIDEVICEINIT, TestCodecDaiDeviceInit},
    {AUDIO_DRIVER_TESTCODECDAIHWPARAMS, TestCodecDaiHwParams},
    {AUDIO_DRIVER_TESTCODECDAISTARTUP, TestCodecDaiStartup},

    {AUDIO_DRIVER_TESTAIAOHALSYSINIT, TestAiaoHalSysInit},
    {AUDIO_DRIVER_TESTAIAOCLOCKRESET, TestAiaoClockReset},
    {AUDIO_DRIVER_TESTAIAOHALREADREG, TestAiaoHalReadReg},
    {AUDIO_DRIVER_TESTAOPHALSETBUFFRPTR, TestAopHalSetBuffRptr},
    {AUDIO_DRIVER_TESTAOPHALSETBUFFWPTR, TestAopHalSetBuffWptr},
    {AUDIO_DRIVER_TESTAOPHALSETBUFFERADDR, TestAopHalSetBufferAddr},
    {AUDIO_DRIVER_TESTAIPHALSETBUFFERADDR, TestAipHalSetBufferAddr},
    {AUDIO_DRIVER_TESTAIPHALSETBUFFERSIZE, TestAipHalSetBufferSize},
    {AUDIO_DRIVER_TESTAIPHALSETTRANSSIZE, TestAipHalSetTransSize},
    {AUDIO_DRIVER_TESTAIPHALSETRXSTART, TestAipHalSetRxStart},
    {AUDIO_DRIVER_TESTAIPHALSETBUFFWPTR, TestAipHalSetBuffWptr},
    {AUDIO_DRIVER_TESTAIPHALSETBUFFRPTR, TestAipHalSetBuffRptr},
    {AUDIO_DRIVER_TESTAOPHALSETBUFFERSIZE, TestAopHalSetBufferSize},
    {AUDIO_DRIVER_TESTAOPHALSETTRANSSIZE, TestAopHalSetTransSize},
    {AUDIO_DRIVER_TESTAOPHALSETTXSTART, TestAopHalSetTxStart},
    {AUDIO_DRIVER_TESTAOPHALDEVENABLE, TestAopHalDevEnable},
    {AUDIO_DRIVER_TESTAIPBUFFRPTRREG, TestAipBuffRptrReg},
    {AUDIO_DRIVER_TESTAIPBUFFWPTRREG, TestAipBuffWptrReg},
    {AUDIO_DRIVER_TESTAOPBUFFRPTRREG, TestAopBuffRptrReg},
    {AUDIO_DRIVER_TESTAOPBUFFWPTRREG, TestAopBuffWptrReg},
    {AUDIO_DRIVER_TESTAOPSETSYSCTLREG, TestAopSetSysCtlReg},
    {AUDIO_DRIVER_TESTAOPSETATTR, TestAopSetAttr},
    {AUDIO_DRIVER_TESTAIPSETSYSCTLREG, TestAipSetSysCtlReg},
    {AUDIO_DRIVER_TESTAIPSETATTR, TestAipSetAttr},
    {AUDIO_DRIVER_TESTAIAODEVICEINIT, TestAiaoDeviceInit},
    {AUDIO_DRIVER_TESTI2SCRGCFGINIT, TestI2sCrgCfgInit},
};

int32_t HdfAudioDriverEntry(HdfTestMsg *msg)
{
    int32_t result;
    uint32_t i;

    if (msg == NULL) {
        HDF_LOGE("%s is fail: HdfTestMsg is NULL!", __func__);
        return HDF_SUCCESS;
    }

    for (i = 0; i < sizeof(g_hdfHi3516DirverTestCaseList) / sizeof(g_hdfHi3516DirverTestCaseList[0]); ++i) {
        if ((msg->subCmd == g_hdfHi3516DirverTestCaseList[i].subCmd) &&
            (g_hdfHi3516DirverTestCaseList[i].testFunc != NULL)) {
            result = g_hdfHi3516DirverTestCaseList[i].testFunc();
            HDF_LOGE("HdfAudioDriverEntry::hi3516 driver test result[%s-%u]",
                     ((result == 0) ? "pass" : "fail"), msg->subCmd);
            msg->result = (result == 0) ? HDF_SUCCESS : HDF_FAILURE;
            return HDF_SUCCESS;
        }
    }

    return HDF_SUCCESS;
}

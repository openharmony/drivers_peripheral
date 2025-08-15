/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include "lpp_log.h"
#include "low_power_player_factory.h"
#include "lpp_sync_manager_adapter.h"
namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

static std::mutex mutex_;
static std::shared_ptr<void> libHandle_ = nullptr;
static GetAVCapabilityFunc capVdi_ = nullptr;

extern "C" ILowPowerPlayerFactory* LowPowerPlayerFactoryImplGetInstance(void)
{
    return new (std::nothrow) LowPowerPlayerFactory();
}

extern "C" void LowPowerPlayerFactoryImplRelease(void* ptr)
{
    delete (LowPowerPlayerFactory*)ptr;
}

int32_t LowPowerPlayerFactory::CreateSyncMgr(sptr<ILppSyncManagerAdapter> &lppAdapter)
{
    sptr<LppSyncManagerAdapter> lppInstance = sptr<LppSyncManagerAdapter>::MakeSptr();
    int32_t ret = lppInstance->Init();
    CHECK_TRUE_RETURN_RET_LOG(ret != HDF_SUCCESS, HDF_FAILURE, "create vdi failed");
    lppAdapter = lppInstance;
    return HDF_SUCCESS;
}

int32_t LowPowerPlayerFactory::CreateAudioSink(sptr<ILppAudioSinkAdapter>& audioSinkAdapter)
{
    return HDF_SUCCESS;
}

int32_t LowPowerPlayerFactory::GetAVCapability(LppAVCap& avCap)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (libHandle_ == nullptr) {
        void *handle = dlopen(LOW_POWER_PLAYER_VDI_LIBRARY, RTLD_LAZY);
        CHECK_TRUE_RETURN_RET_LOG(handle == NULL, HDF_FAILURE, "dlopen failed, %{public}s", dlerror());
        libHandle_ = std::shared_ptr<void>(handle, dlclose); // use smart pointer to manage library handle
    }
    if (capVdi_ == nullptr) {
        capVdi_ = reinterpret_cast<GetAVCapabilityFunc>(dlsym(libHandle_.get(), "GetAVCapabilityVdi"));
        CHECK_TRUE_RETURN_RET_LOG(capVdi_ == NULL, HDF_FAILURE, "createVdi_ dlsym failed, %{public}s", dlerror());
    }
    int32_t ret = capVdi_(avCap);
    CHECK_TRUE_RETURN_RET_LOG(ret != HDF_SUCCESS, HDF_FAILURE, "GetAVCapability failed, %{public}s", strerror(errno));
    return ret;
}

}  // namespace V1_0
}  // namespace LowPowerPlayer
}  // namespace HDI
}  // namespace OHOS
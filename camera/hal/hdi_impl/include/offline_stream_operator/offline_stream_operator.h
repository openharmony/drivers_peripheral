/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_OFFLINE_STREAM_OPERATOR_H
#define HOS_CAMERA_OFFLINE_STREAM_OPERATOR_H

#include "camera.h"
#include "offline_stream_operator_service_stub.h"
#include "offline_stream.h"
#include <map>
#include <mutex>

namespace OHOS::Camera {
class OfflineStreamOperator : public OfflineStreamOperatorStub {
public:
    OfflineStreamOperator(OHOS::sptr<IStreamOperatorCallback>& callback);
    virtual ~OfflineStreamOperator();
    virtual CamRetCode CancelCapture(int captureId) override;
    virtual CamRetCode ReleaseStreams(const std::vector<int>& streamIds) override;
    virtual CamRetCode Release() override;

public:
    RetCode CreateOfflineStream(int32_t id, std::shared_ptr<OfflineStreamContext>& context);

private:
    std::shared_ptr<OfflineStream> FindStreamByCaptureId(int32_t captureId);

private:
    std::mutex lock_;
    OHOS::wptr<IStreamOperatorCallback> callback_ = nullptr;
    std::map<int, std::shared_ptr<OfflineStream>> offlineStreamMap_ = {};
};
} // namespace OHOS::Camera
#endif

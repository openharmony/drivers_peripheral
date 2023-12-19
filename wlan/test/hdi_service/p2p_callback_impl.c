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

#include "p2p_callback_impl.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>

static int32_t P2pCallbackDeviceFound(struct IWpaCallback *self,
    const struct HdiP2pDeviceInfoParam *deviceInfoParam, const char *ifName)
{
    (void)self;
    if (deviceInfoParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: srcAddress=" MACSTR, __func__, MAC2STR(deviceInfoParam->srcAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackDeviceLost(struct IWpaCallback *self,
    const struct HdiP2pDeviceLostParam *deviceLostParam, const char *ifName)
{
    (void)self;
    if (deviceLostParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: p2pDeviceAddress=" MACSTR, __func__, MAC2STR(deviceLostParam->p2pDeviceAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGoNegotiationRequest(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationRequestParam *goNegotiationRequestParam, const char *ifName)
{
    (void)self;
    if (goNegotiationRequestParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: srcAddress=" MACSTR, __func__, MAC2STR(goNegotiationRequestParam->srcAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGoNegotiationCompleted(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationCompletedParam *goNegotiationCompletedParam, const char *ifName)
{
    (void)self;
    if (goNegotiationCompletedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: status=%{public}d", __func__, goNegotiationCompletedParam->status);
    return HDF_SUCCESS;
}

static int32_t P2pCallbackInvitationReceived(struct IWpaCallback *self,
    const struct HdiP2pInvitationReceivedParam *invitationReceivedParam, const char *ifName)
{
    (void)self;
    if (invitationReceivedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: srcAddress=" MACSTR, __func__, MAC2STR(invitationReceivedParam->srcAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackInvitationResult(struct IWpaCallback *self,
    const struct HdiP2pInvitationResultParam *invitationResultParam, const char *ifName)
{
    (void)self;
    if (invitationResultParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: bssid=" MACSTR, __func__, MAC2STR(invitationResultParam->bssid));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGroupFormationSuccess(struct IWpaCallback *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: GroupFormationSuccess", __func__);
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGroupFormationFailure(struct IWpaCallback *self,
    const char *reason, const char *ifName)
{
    (void)self;
    if (reason == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HDF_LOGE("%{public}s: reason=%{public}s", __func__, reason);
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGroupStarted(struct IWpaCallback *self,
    const struct HdiP2pGroupStartedParam *groupStartedParam, const char *ifName)
{
    (void)self;
    if (groupStartedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: goDeviceAddress=" MACSTR, __func__, MAC2STR(groupStartedParam->goDeviceAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackGroupRemoved(struct IWpaCallback *self,
    const struct HdiP2pGroupRemovedParam *groupRemovedParam, const char *ifName)
{
    (void)self;
    if (groupRemovedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: isGo=%{public}d groupIfName=%{public}s", __func__, groupRemovedParam->isGo,
        groupRemovedParam->groupIfName);
    return HDF_SUCCESS;
}

static int32_t P2pCallbackProvisionDiscoveryCompleted(struct IWpaCallback *self,
    const struct HdiP2pProvisionDiscoveryCompletedParam *param, const char *ifName)
{
    (void)self;
    if (param == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: p2pDeviceAddress=" MACSTR, __func__, MAC2STR(param->p2pDeviceAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackFindStopped(struct IWpaCallback *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: FindStopped", __func__);
    return HDF_SUCCESS;
}

static int32_t P2pCallbackServDiscReq(struct IWpaCallback *self,
    const struct HdiP2pServDiscReqInfoParam *servDiscReqInfoParam, const char *ifName)
{
    (void)self;
    if (servDiscReqInfoParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: mac=" MACSTR, __func__, MAC2STR(servDiscReqInfoParam->mac));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackServDiscResp(struct IWpaCallback *self,
    const struct HdiP2pServDiscRespParam *param, const char *ifName)
{
    (void)self;
    if (param == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: srcAddress=" MACSTR, __func__, MAC2STR(param->srcAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackStaConnectState(struct IWpaCallback *self,
    const struct HdiP2pStaConnectStateParam *param, const char *ifName)
{
    (void)self;
    if (param == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: srcAddress=" MACSTR "p2pDeviceAddress=" MACSTR, __func__, MAC2STR(param->srcAddress),
        MAC2STR(param->p2pDeviceAddress));
    return HDF_SUCCESS;
}

static int32_t P2pCallbackIfaceCreated(struct IWpaCallback *self,
    const struct HdiP2pIfaceCreatedParam *param, const char *ifName)
{
    (void)self;
    if (param == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: isGo=%{public}d", __func__, param->isGo);
    return HDF_SUCCESS;
}

struct IWpaCallback *P2pCallbackServiceGet(void)
{
    struct P2pCallbackService *service =
        (struct P2pCallbackService *)OsalMemCalloc(sizeof(struct P2pCallbackService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc P2pCallbackService obj failed!", __func__);
        return NULL;
    }

    service->interface.OnEventDeviceFound = P2pCallbackDeviceFound;
    service->interface.OnEventDeviceLost = P2pCallbackDeviceLost;
    service->interface.OnEventGoNegotiationRequest = P2pCallbackGoNegotiationRequest;
    service->interface.OnEventGoNegotiationCompleted = P2pCallbackGoNegotiationCompleted;
    service->interface.OnEventInvitationReceived = P2pCallbackInvitationReceived;
    service->interface.OnEventInvitationResult = P2pCallbackInvitationResult;
    service->interface.OnEventGroupFormationSuccess = P2pCallbackGroupFormationSuccess;
    service->interface.OnEventGroupFormationFailure = P2pCallbackGroupFormationFailure;
    service->interface.OnEventGroupStarted = P2pCallbackGroupStarted;
    service->interface.OnEventGroupRemoved = P2pCallbackGroupRemoved;
    service->interface.OnEventProvisionDiscoveryCompleted = P2pCallbackProvisionDiscoveryCompleted;
    service->interface.OnEventFindStopped = P2pCallbackFindStopped;
    service->interface.OnEventServDiscReq = P2pCallbackServDiscReq;
    service->interface.OnEventServDiscResp = P2pCallbackServDiscResp;
    service->interface.OnEventStaConnectState = P2pCallbackStaConnectState;
    service->interface.OnEventIfaceCreated = P2pCallbackIfaceCreated;
    return &service->interface;
}

void P2pCallbackServiceRelease(struct IWpaCallback *instance)
{
    struct P2pCallbackService *service = (struct P2pCallbackService *)instance;
    if (service == NULL) {
        return;
    }

    OsalMemFree(service);
}

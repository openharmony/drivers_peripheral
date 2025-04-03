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
#ifndef WPA_P2P_CMD_H
#define WPA_P2P_CMD_H
 
#include "../wpa_impl.h"
#include "wpa_client.h"

/**
 * @brief Defines the enum for P2p Wps Method
 *
 * @since 4.1
 * @version 1.0
 */
enum P2pWpsMethod {
    P2P_WPS_METHOD_PBC,
    P2P_WPS_METHOD_DISPLAY,
    P2P_WPS_METHOD_KEYPAD,
    P2P_WPS_METHOD_LABEL,
    P2P_WPS_METHOD_INVALID
};

enum P2pRemoveGroupEvent {
    P2P_REMOVE_GROUP_CLIENT = 0,
    P2P_REJECT,
    P2P_SET_MIRACAST_SINK_CONFIG,
    EVENT_MAX
};

int32_t WpaInterfaceP2pSetSsidPostfixName(struct IWpaInterface *self, const char *ifName, const char *name);

int32_t WpaInterfaceP2pSetWpsDeviceType(struct IWpaInterface *self, const char *ifName, const char *type);

int32_t WpaInterfaceP2pSetWpsConfigMethods(struct IWpaInterface *self, const char *ifName, const char *methods);

int32_t WpaInterfaceP2pSetGroupMaxIdle(struct IWpaInterface *self, const char *ifName, int32_t time);

int32_t WpaInterfaceP2pSetWfdEnable(struct IWpaInterface *self, const char *ifName, int32_t enable);

int32_t WpaInterfaceP2pSetPersistentReconnect(struct IWpaInterface *self, const char *ifName, int32_t status);

int32_t WpaInterfaceP2pSetWpsSecondaryDeviceType(struct IWpaInterface *self, const char *ifName, const char *type);

int32_t WpaInterfaceP2pSetupWpsPbc(struct IWpaInterface *self, const char *ifName, const char *address);

int32_t WpaInterfaceP2pSetupWpsPin(struct IWpaInterface *self, const char *ifName, const char *address,
    const char *pin, char *result, uint32_t resultLen);

int32_t WpaInterfaceP2pSetPowerSave(struct IWpaInterface *self, const char *ifName, int32_t enable);

int32_t WpaInterfaceP2pSetDeviceName(struct IWpaInterface *self, const char *ifName, const char *name);

int32_t WpaInterfaceP2pSetWfdDeviceConfig(struct IWpaInterface *self, const char *ifName, const char *config);

int32_t WpaInterfaceP2pSetRandomMac(struct IWpaInterface *self, const char *ifName, int32_t networkId);

int32_t WpaInterfaceP2pStartFind(struct IWpaInterface *self, const char *ifName, int32_t timeout);

int32_t WpaInterfaceP2pSetExtListen(struct IWpaInterface *self, const char *ifName, int32_t enable,
    int32_t period, int32_t interval);

int32_t WpaInterfaceP2pSetListenChannel(struct IWpaInterface *self, const char *ifName, int32_t channel,
    int32_t regClass);

int32_t WpaInterfaceP2pProvisionDiscovery(struct IWpaInterface *self, const char *ifName,
    const char *peerBssid, int32_t mode);

int32_t WpaInterfaceP2pAddGroup(struct IWpaInterface *self, const char *ifName, int32_t isPersistent,
    int32_t networkId, int32_t freq);

int32_t WpaInterfaceP2pAddService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info);

int32_t WpaInterfaceP2pRemoveService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info);

int32_t WpaInterfaceP2pStopFind(struct IWpaInterface *self, const char *ifName);

int32_t WpaInterfaceP2pFlush(struct IWpaInterface *self, const char *ifName);

int32_t WpaInterfaceP2pFlushService(struct IWpaInterface *self, const char *ifName);

int32_t WpaInterfaceP2pRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId);

int32_t WpaInterfaceP2pSetGroupConfig(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *name, const char *value);

int32_t WpaInterfaceP2pInvite(struct IWpaInterface *self, const char *ifName, const char *peerBssid,
    const char *goBssid);

int32_t WpaInterfaceP2pReinvoke(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *bssid);

int32_t WpaInterfaceP2pGetDeviceAddress(struct IWpaInterface *self, const char *ifName, char *deviceAddress,
    uint32_t deviceAddressLen);

int32_t WpaInterfaceP2pReqServiceDiscovery(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pReqService *reqService, char *replyDisc, uint32_t replyDiscLen);

int32_t WpaInterfaceP2pCancelServiceDiscovery(struct IWpaInterface *self, const char *ifName, const char *id);

int32_t WpaInterfaceP2pRespServerDiscovery(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServDiscReqInfo *info);

int32_t WpaInterfaceP2pConnect(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pConnectInfo *info, char *replyPin, uint32_t replyPinLen);

int32_t WpaInterfaceP2pHid2dConnect(struct IWpaInterface *self, const char *ifName,
    const struct HdiHid2dConnectInfo *info);

int32_t WpaInterfaceP2pSetServDiscExternal(struct IWpaInterface *self, const char *ifName, int32_t mode);

int32_t WpaInterfaceP2pRemoveGroup(struct IWpaInterface *self, const char *ifName, const char *groupName);

int32_t WpaInterfaceP2pCancelConnect(struct IWpaInterface *self, const char *ifName);

int32_t WpaInterfaceP2pGetGroupConfig(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *param, char *value, uint32_t valueLen);

int32_t WpaInterfaceP2pAddNetwork(struct IWpaInterface *self, const char *ifName, int32_t *networkId);

int32_t WpaInterfaceP2pGetPeer(struct IWpaInterface *self, const char *ifName, const char *bssid,
    struct HdiP2pDeviceInfo *info);

int32_t WpaInterfaceP2pGetGroupCapability(struct IWpaInterface *self, const char *ifName, const char *bssid,
    int32_t *cap);

int32_t WpaInterfaceP2pListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiP2pNetworkList *infoList);

int32_t WpaInterfaceP2pSaveConfig(struct IWpaInterface *self, const char *ifName);

int32_t WpaInterfaceVendorExtProcessCmd(struct IWpaInterface *self, const char *ifName, const char *cmd);

int32_t WpaInterfaceDeliverP2pData(struct IWpaInterface *self, const char *ifName,
    int32_t cmdType, int32_t dataType, const char *carryData);
/**
 * @brief Defines callback for P2p
 *
 * @since 4.1
 * @version 1.0
 */
int32_t ProcessEventP2pDeviceFound(struct HdfWpaRemoteNode *node,
    struct P2pDeviceInfoParam *deviceInfoParam, const char *ifName);

int32_t ProcessEventP2pDeviceLost(struct HdfWpaRemoteNode *node,
    struct P2pDeviceLostParam *deviceLostParam, const char *ifName);

int32_t ProcessEventP2pGoNegotiationRequest(struct HdfWpaRemoteNode *node,
    struct P2pGoNegotiationRequestParam *goNegotiationRequestParam, const char *ifName);

int32_t ProcessEventP2pGoNegotiationCompleted(struct HdfWpaRemoteNode *node,
    struct P2pGoNegotiationCompletedParam *goNegotiationCompletedParam, const char *ifName);

int32_t ProcessEventP2pInvitationReceived(struct HdfWpaRemoteNode *node,
    struct P2pInvitationReceivedParam *invitationReceivedParam, const char *ifName);

int32_t ProcessEventP2pInvitationResult(struct HdfWpaRemoteNode *node,
    struct P2pInvitationResultParam *invitationResultParam, const char *ifName);

int32_t ProcessEventP2pGroupFormationSuccess(struct HdfWpaRemoteNode *node,
    const char *ifName);

int32_t ProcessEventP2pGroupFormationFailure(struct HdfWpaRemoteNode *node, char *reason,
    const char *ifName);

int32_t ProcessEventP2pGroupStarted(struct HdfWpaRemoteNode *node,
    struct P2pGroupStartedParam *groupStartedParam, const char *ifName);

int32_t ProcessEventP2pGroupRemoved(struct HdfWpaRemoteNode *node,
    struct P2pGroupRemovedParam *groupRemovedParam, const char *ifName);

int32_t ProcessEventP2pProvisionDiscoveryCompleted(struct HdfWpaRemoteNode *node,
    struct P2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char *ifName);

int32_t ProcessEventP2pFindStopped(struct HdfWpaRemoteNode *node,
    const char *ifName);

int32_t ProcessEventP2pServDiscReq(struct HdfWpaRemoteNode *node,
    struct P2pServDiscReqInfoParam *servDiscReqInfo, const char *ifName);

int32_t ProcessEventP2pServDiscResp(struct HdfWpaRemoteNode *node,
    struct P2pServDiscRespParam *servDiscRespParam, const char *ifName);

int32_t ProcessEventP2pStaConnectState(struct HdfWpaRemoteNode *node,
    struct P2pStaConnectStateParam *staConnectStateParam, const char *ifName);

int32_t ProcessEventP2pIfaceCreated(struct HdfWpaRemoteNode *node, struct P2pIfaceCreatedParam *ifaceCreatedParam,
    const char *ifName);

#endif

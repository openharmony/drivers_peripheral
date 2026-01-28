/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ai hold posture info
 * Create: 2025-02-06
 */
#ifndef HOLD_POSTURE_INFO_H
#define HOLD_POSTURE_INFO_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {

class HoldPostureInfo : public Parcelable {
public:
    /**
    * @brief AI计算返回的type
    */
    enum class Type {
        ERROR = -2,
        UNKNOWN,
        LEFT_HAND_PORTRAIT_INV,  // 反向竖屏左手持
        RIGHT_HAND_PORTRAIT_INV,  // 反向竖屏右手持
        LEFT_HAND_LANDSCAPE_CAMERA_LEFT,  // 摄像头朝左横屏左手持
        LEFT_HAND_LANDSCAPE_CAMERA_RIGHT,  // 摄像头朝右横屏左手持
        RIGHT_HAND_LANDSCAPE_CAMERA_LEFT,  // 摄像头朝左横屏右手持
        RIGHT_HAND_LANDSCAPE_CAMERA_RIGHT,  // 摄像头朝右横屏右手持
        BOTH_HAND_LANDSCAPE_CAMERA_LEFT,  // 摄像头朝左横屏双手持
        BOTH_HAND_LANDSCAPE_CAMERA_RIGHT,  // 摄像头朝右横屏双手持
        LEFT_HAND_PORTRAIT,  // 竖屏左手持
        RIGHT_HAND_PORTRAIT,  // 竖屏右手持
        BOTH_HAND_PORTRAIT_INV,  // 反向竖屏双手持
        TABLE,  // 放置桌面
        BOTH_HAND_PORTRAIT,  // 竖屏双手持
        TYPE_MAX
    };

    ~HoldPostureInfo() override;

    /**
    * @brief 设置业务方回调接收到的type
    * @param HoldPostureInfo::Type 传入要设置的type
    * @return 返回设置成功或失败
    */
    bool SetType(HoldPostureInfo::Type type);

    /**
    * @brief 获取当前的type
    * @return 返回当前的type
    */
    HoldPostureInfo::Type GetType() const;

    /**
    * @brief 将当前的type转换成字符串类型
    * @return 返回type对应的字符串
    */
    std::string ToString();

    /**
    * @brief 序列化type
    * @param HoldPostureInfo::Type 传入要序列化的type
    * @return 返回序列化成功或失败
    */
    bool Marshalling(Parcel &parcel) const override;

    /**
    * @brief 读取序列化的type
    * @param Parcel 传入序列化的type
    * @return 返回读取序列化成功或失败
    */
    bool ReadFromParcel(Parcel &parcel);

private:
    HoldPostureInfo::Type holdPostureType_;
    // 定义枚举到字符串的映射
    static const std::unordered_map<HoldPostureInfo::Type, std::string> typeToStringMap_;
};

enum class HoldPostureErrorCode {
    SUCCESS = 0,
    PREDICT_FAIL,
    SENSOR_DATA_NOT_UPDATE,
    SENSOR_SDC_ADDRESS_ERROR,
    SENSOR_DATA_ERROR,
    MAP_OVERSIZE_ERROR,
    FILE_NOT_FOUND,
    FILE_EMPTY,
    FILE_FORMAT_ERROR,
    CONFIG_ERROR,
    PERMISSION_DENIED,
    FEATURE_DISABLE,
    CALLBACK_IS_NULL,
    CALLBACK_IS_AREADY_REGISTERED,
    CALLBACK_NOT_FOUND,
    CALLBACK_DEAD,
    SENSOR_INIT_ERROR,
    SIGNALHUB_OPEN_ERROR,
    AI_INIT_ERROR,
    AI_STOP,
    // sensorhub侧error code 30~50，只能追加，不能插入
    SENSORHUB_ERR_CODE_START = 30,
    DATA_LOSS_ERR,
    SENSOR_REG_ERR,
    TRI_NOTIFY_AI_FAIL,
	ATOM_REG_FAIL,
	ATOM_GET_DATA_FAIL,
	FUSION_REG_FAIL,
    FUSION_DATA_ERROR,
	FUSION_UPLOAD_FAIL,
    PREPROCESS_ERROR,
    SENSORHUB_ERR_CODE_END = 50,
    ERROR_CODE_MAX
};

} // namespace Telephony
} // namespace OHOS
#endif // HOLD_POSTURE_INFO_H

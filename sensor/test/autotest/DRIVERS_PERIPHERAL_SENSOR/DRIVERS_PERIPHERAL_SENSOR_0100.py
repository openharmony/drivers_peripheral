#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from devicetest.core.test_case import TestCase, Step
from hypium import *
from hypium.uiexplorer import *


class DRIVERS_PERIPHERAL_SENSOR_0100(TestCase):
    def __init__(self, configs):
        self.TAG = self.__class__.__name__
        TestCase.__init__(self, self.TAG, configs)

    def setup(self):
        Step("预置工作:初始化设备")
        driver = UiDriver.create(self.device1)
        wake = driver.Screen.is_on()
        time.sleep(0.5)
        if wake:
            driver.ScreenLock.unlock()
        else:
            driver.Screen.wake_up()
            driver.ScreenLock.unlock()
        driver.shell("power-shell timeout -o 86400000")

    def process(self):
        Step("验证指南针传感器功能")
        driver = UiDriver.create(self.device1)

        Step("清空hilog缓冲区")
        driver.shell("hilog -r")
        
        Step("步骤1:打开指南针应用")
        driver.start_app("com.huawei.hmsapp.compass")
        time.sleep(2)

        Step("步骤2:关闭指南针应用")
        driver.stop_app("com.huawei.hmsapp.compass")

        Step("步骤3:检查hilog日志验证传感器数据上报")
        time.sleep(1)
        log_output = driver.shell("hilog -x | grep 'sensor_host/cb: {-1,6,0,1}:'")
        import re
        pattern = r"sensor_host/cb: \{-1,6,0,1\}: s=\d+ r=\d+"
        match = re.search(pattern, log_output)
        if match:
            Step(f"传感器数据上报成功，日志内容: {match}")
        else:
            Step("传感器数据上报失败:日志中未检测到磁力计数据")
            raise ValueError('传感器数据上报失败:日志中未检测到磁力计数据')

    def teardown(self):
        Step("收尾工作")
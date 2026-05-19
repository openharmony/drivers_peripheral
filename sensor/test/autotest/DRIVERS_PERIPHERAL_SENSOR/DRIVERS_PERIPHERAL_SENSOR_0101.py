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


class DRIVERS_PERIPHERAL_SENSOR_0101(TestCase):
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
        Step("验证环境光传感器自动调节亮度功能")
        driver = UiDriver.create(self.device1)

        Step("步骤1:打开设置应用")
        driver.start_app("com.huawei.hmos.settings")
        time.sleep(2)

        Step("步骤2:点击显示和亮度选项卡")
        driver.click(BY.text("显示和亮度"))
        time.sleep(1)

        Step("步骤3:将亮度条拖动到最高亮度")
        driver.slide((200, 1974), (1100, 1974), slide_time=3)

        Step("步骤4:关闭自动调节开关")
        driver.touch(BY.key("automatic_adjust_toggle"))
        time.sleep(1)

        Step("步骤5:打开自动调节开关")
        driver.touch(BY.key("automatic_adjust_toggle"))
        time.sleep(2)

        Step("步骤6:检查亮度条是否根据环境光传感器调节到中间值")
        text = driver.get_component_property(BY.key("brightness_slider"), "text")

        Step("步骤7:关闭设置应用")
        driver.stop_app("com.huawei.hmos.settings")

        if 1 < float(text) < 255:
            Step(f"测试通过，亮度根据环境光传感器的值自动适应了, text={text}")
        else:
            Step("测试失败，亮度根据可能没收到环境光传感器数据")
            raise ValueError('测试失败，亮度根据可能没收到环境光传感器数据')

    def teardown(self):
        Step("收尾工作")

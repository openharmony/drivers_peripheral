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

import sys
from xdevice.__main__ import main_process

if __name__ == "__main__":
    # argv = "{} {} {}".format(sys.argv[1],sys.argv[2],sys.argv[3])
    # print(">>>>>>>： {}".format(argv))
    # main_process(argv)

    # 单个执行
    # main_process('run -l DRIVERS_PERIPHERAL_SENSOR_0101.py')

    # 批量执行
    main_process(r'run -tf testcase.txt')

# Copyright (c) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(PARAM_FILE),)
    PARAM_FILE:=./Makefile.param
    include $(PARAM_FILE)
endif



.PHONY:all buffer_manager hdi_impl init pipeline_core platform device_manager clean

sub_dir := buffer_manager hdi_impl init pipeline_core platform

export OUT_DIR=$(RASP_PATH)/out
#all: $(sub_dir)
all:
	@mkdir -p $(OUT_DIR)
	@cd $(RASP_PATH)/dependency/hdi_impl/ && make

buffer_manager:
	@cd $(RASP_PATH)/buffer_manager/ && make

hdi_impl:
	@cd $(RASP_PATH)/hdi_impl/ && make

init:
	@cd $(RASP_PATH)/init/ && make

pipeline_core:
	@cd $(RASP_PATH)/pipeline_core/ && make

platform:
	@cd $(RASP_PATH)/platform/ && make

device_manager:
	@cd $(RASP_PATH)/device_manager/ && make

clean:
	@cd $(RASP_PATH)/buffer_manager/ && make clean
	@cd $(RASP_PATH)/hdi_impl/ && make clean
	@cd $(RASP_PATH)/init/ && make clean
	@cd $(RASP_PATH)/pipeline_core/ && make clean
	@cd $(RASP_PATH)/platform/ && make clean
	@cd $(RASP_PATH)/device_manager/ && make clean

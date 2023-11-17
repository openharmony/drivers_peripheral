#include "demo.h"
#include <iostream>
#include <stdio.h>
#include <hdf_base.h>
#include <hdf_log.h>

using namespace OHOS;

#define HDF_LOG_TAG clearplay_test_demo

int main(int argc, char *argv[])
{
    printf("hello world!\n");
    HDF_LOGE("hello world!");
    return 0;
}
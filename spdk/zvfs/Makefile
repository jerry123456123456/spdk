# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2017 Intel Corporation
# All rights reserved.

SPDK_ROOT_DIR := $(abspath $(CURDIR)/spdk/)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0
SO_SUFFIX := $(SO_VER).$(SO_MINOR)

LIBNAME = jerryfs
C_SRCS := zv-fs.c

SPDK_MAP_FILE = $(abspath $(CURDIR)/spdk_accel.map)
include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk

# 添加 SPDK 库
LIBS += -L$(SPDK_ROOT_DIR)/build/lib -lspdk_env -lspdk_json -lspdk_subsystem

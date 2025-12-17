# CMakeLists.txt - HDC Library for HarmonyOS
cmake_minimum_required(VERSION 3.16)
project(hdc_napi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译选项
add_definitions(
    -DHDC_HOST                      # 编译为 host 端
    -DHARMONY_PROJECT               # HarmonyOS 项目
    -DHDC_NAPI_LIBRARY              # NAPI 库模式，排除 USB/系统 API
    -DUSE_CONFIG_UV_THREADS         # 使用配置的线程数
    -DSIZE_THREAD_POOL=16           # 线程池大小
    -DOPENSSL_SUPPRESS_DEPRECATED   # 抑制 OpenSSL 废弃警告
    -DHDC_SUPPORT_ENCRYPT_TCP       # 支持 TCP 加密
    -D__OHOS__                      # OHOS 平台标识
    -DHOST_OHOS                     # HOST_OHOS 平台标识（UDS 支持等）
    -DHDC_HILOG                     # 使用 hilog 日志
)

# 不编译 USB 和 UART 相关代码（不定义 HDC_SUPPORT_UART）

# 头文件路径
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/hdc_core/src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/hdc_core/src/host
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/securec
    ${CMAKE_CURRENT_SOURCE_DIR}/napi
)

# LZ4 源码（直接编译，无需静态库）
set(LZ4_SOURCES
    third_party/lz4/src/lz4.c
)

# HDC 公共源文件（排除 USB/UART）
set(HDC_COMMON_SOURCES
    hdc_core/src/common/async_cmd.cpp
    hdc_core/src/common/auth.cpp
    hdc_core/src/common/base.cpp
    hdc_core/src/common/channel.cpp
    hdc_core/src/common/circle_buffer.cpp
    # hdc_core/src/common/command_event_report.cpp  # 排除：依赖系统 API
    hdc_core/src/common/compress.cpp
    hdc_core/src/common/credential_message.cpp
    hdc_core/src/common/decompress.cpp
    hdc_core/src/common/entry.cpp
    hdc_core/src/common/file.cpp
    hdc_core/src/common/file_descriptor.cpp
    hdc_core/src/common/forward.cpp
    # hdc_core/src/common/hdc_huks.cpp  # 排除：依赖 HUKS 系统 API
    hdc_core/src/common/hdc_ssl.cpp
    hdc_core/src/common/hdc_statistic_reporter.cpp  # 空实现，不依赖系统 API（除非定义 HDC_STATISTIC_REPORT_ENABLE）
    hdc_core/src/common/header.cpp
    hdc_core/src/common/heartbeat.cpp
    hdc_core/src/common/memory_pool.cpp
    hdc_core/src/common/password.cpp
    hdc_core/src/common/server_cmd_log.cpp
    hdc_core/src/common/session.cpp
    hdc_core/src/common/task.cpp
    hdc_core/src/common/tcp.cpp
    hdc_core/src/common/tlv.cpp
    hdc_core/src/common/transfer.cpp
    hdc_core/src/common/uv_status.cpp
    # 注意：不包含 usb.cpp 和 uart.cpp
)

# HDC Host 端源文件（排除 USB/UART/Server）
set(HDC_HOST_SOURCES
    hdc_core/src/host/client.cpp
    hdc_core/src/host/ext_client.cpp
    hdc_core/src/host/host_app.cpp
    hdc_core/src/host/host_forward.cpp
    hdc_core/src/host/host_tcp.cpp
    hdc_core/src/host/host_unity.cpp
    hdc_core/src/host/host_ssl.cpp
    hdc_core/src/host/host_shell_option.cpp
    hdc_core/src/host/host_updater.cpp
    hdc_core/src/host/translate.cpp
    hdc_core/src/host/system_depend.cpp
    hdc_core/src/host/server_stub.cpp  # Stub for HdcServer::PullupServer
    # 注意：不包含 host_usb.cpp、host_uart.cpp
    # 注意：不包含 server.cpp、server_for_client.cpp（不需要 server 功能）
    # 注意：不包含 main.cpp（使用 NAPI 入口）
)

# NAPI 源文件
set(NAPI_SOURCES
    napi/hdc_napi.cpp
    napi/hdc_client_wrapper.cpp
)

# 构建共享库
add_library(hdc_napi SHARED
    ${HDC_COMMON_SOURCES}
    ${HDC_HOST_SOURCES}
    ${NAPI_SOURCES}
    ${LZ4_SOURCES}
)

# 链接库
# libuv - 使用系统动态库
# openssl - 使用 third_party 中的静态库
# lz4 - 直接编译源码，无需链接
target_link_libraries(hdc_napi
    libuv.so
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl/lib/${OHOS_ARCH}/libssl.a
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl/lib/${OHOS_ARCH}/libcrypto.a
    libace_napi.z.so
    libhilog_ndk.z.so
)

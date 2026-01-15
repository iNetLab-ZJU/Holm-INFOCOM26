cmake_minimum_required(VERSION 3.22)
project(simple_fwd_vnf C)

# —— C 标准 & 构建类型 ——
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)

# —— DOCA SDK 路径 & pkg-config ——
set(DOCA_SDK_ROOT /opt/mellanox/doca)
set(ENV{PKG_CONFIG_PATH}
        "${DOCA_SDK_ROOT}/lib/aarch64-linux-gnu/pkgconfig:$ENV{PKG_CONFIG_PATH}"
)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# —— 通过 pkg-config 查找 DOCA 各模块 ——
pkg_check_modules(DOCA_COMMON REQUIRED doca-common)
pkg_check_modules(DOCA_ETH    REQUIRED doca-eth)
pkg_check_modules(DOCA_FLOW   REQUIRED doca-flow)
pkg_check_modules(DOCA_ARGP   REQUIRED doca-argp)
pkg_check_modules(DOCA_COMCH  REQUIRED doca-comch)

# —— DPDK 库目录 ——
set(DPDK_LIB_PATH /opt/mellanox/dpdk/lib/aarch64-linux-gnu)

# —— 包含头文件 ——
include_directories(
        ${CMAKE_SOURCE_DIR}
        ${DOCA_SDK_ROOT}/applications/common
        ${DOCA_COMMON_INCLUDE_DIRS}
        ${DOCA_ETH_INCLUDE_DIRS}
        ${DOCA_FLOW_INCLUDE_DIRS}
        ${DOCA_ARGP_INCLUDE_DIRS}
        ${DOCA_COMCH_INCLUDE_DIRS}
)

# —— 链接搜索路径 ——
link_directories(
        ${DOCA_COMMON_LIBRARY_DIRS}
        ${DOCA_ETH_LIBRARY_DIRS}
        ${DOCA_FLOW_LIBRARY_DIRS}
        ${DOCA_ARGP_LIBRARY_DIRS}
        ${DOCA_COMCH_LIBRARY_DIRS}
        ${DPDK_LIB_PATH}
)

# —— 源文件列表 ——
set(APP_SRCS
        ${CMAKE_SOURCE_DIR}/simple_fwd_vnf.c
        ${CMAKE_SOURCE_DIR}/simple_fwd.c
        ${CMAKE_SOURCE_DIR}/simple_fwd_ft.c
        ${CMAKE_SOURCE_DIR}/simple_fwd_pkt.c
        ${CMAKE_SOURCE_DIR}/simple_fwd_port.c
        ${CMAKE_SOURCE_DIR}/simple_fwd_vnf_core.c
        ${CMAKE_SOURCE_DIR}/dpdk_utils.c
        ${DOCA_SDK_ROOT}/applications/common/utils.c
)

# —— 单一可执行文件 ——
add_executable(simple-fwd-vnf ${APP_SRCS})
target_link_libraries(simple-fwd-vnf PRIVATE
        Threads::Threads
        ${DOCA_COMMON_LIBRARIES}
        ${DOCA_ETH_LIBRARIES}
        ${DOCA_FLOW_LIBRARIES}
        ${DOCA_ARGP_LIBRARIES}
        ${DOCA_COMCH_LIBRARIES}
        ${DOCA_COMMON_LDFLAGS_OTHER}
        ${DOCA_ETH_LDFLAGS_OTHER}
        ${DOCA_FLOW_LDFLAGS_OTHER}
        ${DOCA_ARGP_LDFLAGS_OTHER}
        ${DOCA_COMCH_LDFLAGS_OTHER}
        rte_eal
        rte_ethdev
        rte_mbuf
        rte_mempool
        rte_ring
        rte_net
        rte_hash
)
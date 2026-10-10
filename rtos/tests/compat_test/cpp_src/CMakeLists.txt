cmake_minimum_required(VERSION 3.16)
project(compat_test_node)

# Require paths to be set
if(NOT DEFINED TOS_SRC_PATH)
    message(FATAL_ERROR "TOS_SRC_PATH must be defined. Pass -DTOS_SRC_PATH=/path/to/ton-cpp-testnet")
endif()

if(NOT DEFINED TOS_BUILD_PATH)
    # Default to build directory inside source
    set(TOS_BUILD_PATH "${TOS_SRC_PATH}/build")
endif()

if(NOT EXISTS "${TOS_SRC_PATH}/adnl")
    message(FATAL_ERROR "TOS_SRC_PATH (${TOS_SRC_PATH}) does not appear to be a valid TOS source directory")
endif()

if(NOT EXISTS "${TOS_BUILD_PATH}")
    message(FATAL_ERROR "TOS_BUILD_PATH (${TOS_BUILD_PATH}) does not exist. Please build TOS first:\n"
                        "  cd ${TOS_SRC_PATH}\n"
                        "  mkdir build && cd build\n"
                        "  cmake ..\n"
                        "  cmake --build . --target overlay adnl adnltest dht tl_api keys keyring fec rldp rldp2 tdutils tdactor tdnet ton_crypto")
endif()

message(STATUS "Using TOS source: ${TOS_SRC_PATH}")
message(STATUS "Using TOS build: ${TOS_BUILD_PATH}")

# Set C++ standard (TOS requires C++20 for 'requires' expressions)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages (same as TOS uses)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Our test binary
add_executable(compat_test_node
    compat_test_node.cpp
)

# Include directories from TOS source
target_include_directories(compat_test_node PRIVATE
    ${TOS_SRC_PATH}
    ${TOS_SRC_PATH}/tdutils
    ${TOS_SRC_PATH}/tdactor
    ${TOS_SRC_PATH}/tdnet
    ${TOS_SRC_PATH}/crypto
    ${TOS_SRC_PATH}/tl
    ${TOS_SRC_PATH}/tl-utils
    ${TOS_SRC_PATH}/keys
    ${TOS_SRC_PATH}/keyring
    ${TOS_SRC_PATH}/adnl
    ${TOS_SRC_PATH}/overlay
    ${TOS_SRC_PATH}/rldp
    ${TOS_SRC_PATH}/rldp2
    ${TOS_SRC_PATH}/fec
    ${TOS_SRC_PATH}/tdfec
    ${TOS_SRC_PATH}/quic
    ${TOS_SRC_PATH}/metrics
    ${TOS_SRC_PATH}/tddb
    ${TOS_SRC_PATH}/third-party/abseil-cpp
    ${TOS_SRC_PATH}/third-party/ngtcp2/lib/includes
    ${TOS_SRC_PATH}/third-party/ngtcp2/crypto/includes
    ${TOS_BUILD_PATH}/third-party/ngtcp2/lib/includes
    ${TOS_SRC_PATH}/tl/generate  # For auto-generated TL headers
    ${TOS_BUILD_PATH}
    ${TOS_BUILD_PATH}/tdutils
)

# Find libraries in TOS build directory
set(TOS_LIB_DIRS
    ${TOS_BUILD_PATH}/overlay
    ${TOS_BUILD_PATH}/adnl
    ${TOS_BUILD_PATH}/dht
    ${TOS_BUILD_PATH}/rldp
    ${TOS_BUILD_PATH}/rldp2
    ${TOS_BUILD_PATH}/fec
    ${TOS_BUILD_PATH}/tl
    ${TOS_BUILD_PATH}/tl-utils
    ${TOS_BUILD_PATH}/keys
    ${TOS_BUILD_PATH}/keyring
    ${TOS_BUILD_PATH}/tdutils
    ${TOS_BUILD_PATH}/tdactor
    ${TOS_BUILD_PATH}/tdnet
    ${TOS_BUILD_PATH}/tddb
    ${TOS_BUILD_PATH}/tddb/td/db
    ${TOS_BUILD_PATH}/tdfec
    ${TOS_BUILD_PATH}/tdfec/td/fec
    ${TOS_BUILD_PATH}/crypto
    ${TOS_BUILD_PATH}/common
    ${TOS_BUILD_PATH}/quic
    ${TOS_BUILD_PATH}/metrics
    ${TOS_BUILD_PATH}/third-party/crc32c
    ${TOS_BUILD_PATH}/third-party/libraptorq
    ${TOS_BUILD_PATH}/third-party/rocksdb
    ${TOS_BUILD_PATH}/third-party/ngtcp2/lib
    ${TOS_BUILD_PATH}/third-party/ngtcp2/crypto/ossl
)

# Function to find a library in TOS build dirs
function(find_ton_library VAR_NAME LIB_NAME)
    find_library(${VAR_NAME}
        NAMES ${LIB_NAME}
        PATHS ${TOS_LIB_DIRS}
        PATH_SUFFIXES Release Debug RelWithDebInfo
        NO_DEFAULT_PATH
    )
    if(NOT ${VAR_NAME})
        message(FATAL_ERROR "Could not find TOS library: ${LIB_NAME}\n"
                           "Make sure you have built TOS with: cmake --build . --target ${LIB_NAME}")
    endif()
    message(STATUS "Found ${LIB_NAME}: ${${VAR_NAME}}")
endfunction()

# Find TOS libraries
find_ton_library(TOS_OVERLAY overlay)
find_ton_library(TOS_ADNL adnl)
find_ton_library(TOS_DHT dht)
find_ton_library(TOS_RLDP rldp)
find_ton_library(TOS_RLDP2 rldp2)
find_ton_library(TOS_FEC fec)
find_ton_library(TOS_TL_API tl_api)
find_ton_library(TOS_TL_UTILS tl-utils)
find_ton_library(TOS_KEYS keys)
find_ton_library(TOS_KEYRING keyring)
find_ton_library(TOS_TDUTILS tdutils)
find_ton_library(TOS_TDACTOR tdactor)
find_ton_library(TOS_TDNET tdnet)
find_ton_library(TOS_TDDB tddb)
find_ton_library(TOS_TDFEC tdfec)
find_ton_library(TOS_CRYPTO ton_crypto)
find_ton_library(TOS_CRYPTO_CORE ton_crypto_core)
find_ton_library(TOS_COMMON common)
find_ton_library(TOS_TOS_BLOCK rtos_block)
find_ton_library(TOS_CRC32C crc32c)
find_ton_library(TOS_ROCKSDB rocksdb)
find_ton_library(TOS_QUIC quic)
find_ton_library(TOS_METRICS metrics)

# ngtcp2 libraries (required by quic)
find_library(NGTCP2_LIB
    NAMES ngtcp2
    PATHS ${TOS_BUILD_PATH}/third-party/ngtcp2/lib
    NO_DEFAULT_PATH
)
find_library(NGTCP2_CRYPTO_OSSL_LIB
    NAMES ngtcp2_crypto_ossl
    PATHS ${TOS_BUILD_PATH}/third-party/ngtcp2/crypto/ossl
    NO_DEFAULT_PATH
)

# Optional: RaptorQ library (for FEC)
find_library(RAPTORQ_LIB
    NAMES RaptorQ
    PATHS ${TOS_BUILD_PATH}/third-party/libraptorq
    NO_DEFAULT_PATH
)

target_link_libraries(compat_test_node PRIVATE
    ${TOS_QUIC}
    ${TOS_METRICS}
    ${TOS_OVERLAY}
    ${TOS_ADNL}
    ${TOS_DHT}
    ${TOS_RLDP}
    ${TOS_RLDP2}
    ${TOS_FEC}
    ${TOS_TDFEC}
    ${TOS_TL_API}
    ${TOS_TL_UTILS}
    ${TOS_KEYS}
    ${TOS_KEYRING}
    ${TOS_COMMON}
    ${TOS_TOS_BLOCK}
    ${TOS_TDDB}
    ${TOS_TDUTILS}
    ${TOS_TDACTOR}
    ${TOS_TDNET}
    ${TOS_CRYPTO}
    ${TOS_CRYPTO_CORE}
    ${TOS_CRC32C}
    ${TOS_ROCKSDB}
    OpenSSL::Crypto
    OpenSSL::SSL
    ZLIB::ZLIB
    Threads::Threads
)

# Add ngtcp2 if found (required by quic)
if(NGTCP2_LIB)
    target_link_libraries(compat_test_node PRIVATE ${NGTCP2_LIB})
endif()
if(NGTCP2_CRYPTO_OSSL_LIB)
    target_link_libraries(compat_test_node PRIVATE ${NGTCP2_CRYPTO_OSSL_LIB})
endif()

# Add RaptorQ if found
if(RAPTORQ_LIB)
    target_link_libraries(compat_test_node PRIVATE ${RAPTORQ_LIB})
endif()

# Platform-specific settings
if(APPLE)
    target_link_libraries(compat_test_node PRIVATE
        "-framework Security"
        "-framework CoreFoundation"
        "-framework CoreServices"
    )
    target_link_libraries(compat_test_node PRIVATE c++)
elseif(UNIX)
    target_link_libraries(compat_test_node PRIVATE dl)
endif()

# Add additional libraries that TOS depends on
find_library(LZ4_LIBRARY lz4)
if(LZ4_LIBRARY)
    target_link_libraries(compat_test_node PRIVATE ${LZ4_LIBRARY})
endif()

find_library(SODIUM_LIBRARY sodium)
if(SODIUM_LIBRARY)
    target_link_libraries(compat_test_node PRIVATE ${SODIUM_LIBRARY})
endif()

# blst (BLS crypto, required by ton_crypto)
find_library(BLST_LIBRARY
    NAMES blst
    PATHS ${TOS_BUILD_PATH}/third-party/blst
    NO_DEFAULT_PATH
)
if(BLST_LIBRARY)
    target_link_libraries(compat_test_node PRIVATE ${BLST_LIBRARY})
endif()

# secp256k1 (required by ton_crypto_core)
find_library(SECP256K1_LIBRARY
    NAMES secp256k1
    PATHS ${TOS_BUILD_PATH}/third-party/secp256k1/lib
    NO_DEFAULT_PATH
)
if(SECP256K1_LIBRARY)
    target_link_libraries(compat_test_node PRIVATE ${SECP256K1_LIBRARY})
endif()

# Abseil libraries (required by rtos_block hash containers)
file(GLOB_RECURSE ABSEIL_LIBS "${TOS_BUILD_PATH}/third-party/abseil-cpp/absl/*.a")
if(ABSEIL_LIBS)
    target_link_libraries(compat_test_node PRIVATE ${ABSEIL_LIBS})
endif()

# macOS: re-sign binary to avoid dyld hang caused by com.apple.provenance xattr
if(APPLE)
    add_custom_command(TARGET compat_test_node POST_BUILD
        COMMAND codesign --force --sign - $<TARGET_FILE:compat_test_node>
        COMMENT "Re-signing binary for macOS"
    )
endif()

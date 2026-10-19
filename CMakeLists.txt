# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2026 Ake Hedman and contributors, the VSCP Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# VSCP_PATH - set to path to local vscp repository. Default is "../vscp". Set with
# -DVSCP_PATH="path"
#

cmake_minimum_required(VERSION 3.5)
project(vscpl2drv-socketcan LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# Version settings (YEAR.MONTH.PATCH) are read from src/version.h
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h")
foreach(_ver MAJOR_VERSION MINOR_VERSION PATCH_VERSION)
  if(NOT DEFINED ${_ver})
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h" _line REGEX "^#define[ \t]+${_ver}[ \t]+[0-9]+")
    string(REGEX REPLACE "^#define[ \t]+${_ver}[ \t]+([0-9]+).*" "\\1" ${_ver} "${_line}")
  endif()
endforeach()
message(STATUS "Version: ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")

# Prevent abi warnings in nlohmann
SET(GCC_VSCP_COMPILE_FLAGS "-Wno-psabi")
# Profiling
#SET(GCC_VSCP_LINK_FLAGS    "-lgcov")

SET(CPACK_PACKAGE_DESCRIPTION "VSCP driver for socketcan")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VSCP level II Driver that export an interface to socketcan")
SET(CPACK_PACKAGE_VENDOR "the VSCP Project")
SET(CPACK_PACKAGE_CONTACT "akhe@vscp.org")

if(NOT DEFINED APP_LOW_NAME)
set(APP_LOW_NAME "vscpl2drv-socketcan")
endif()

if(NOT DEFINED APP_NAME)
set(APP_NAME "VSCPL2DEV-WEBSOCKET")
endif()

if(NOT DEFINED APP_URL)
set(APP_URL "https://github.com/grodansparadis/vscpl2drv-socketcan")
endif()

if(NOT DEFINED APP_VERSION)
set(APP_VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
endif()

# Man build and install
if(NOT DEFINED WIN32)
    add_subdirectory(man)
endif()

option(USE_SSL "Use SSL" TRUE)

## --- C++11 build flags ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Generate position-independent code (-fPIC on Unix)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Default location for VSCP level II drivers
set(VSCP_LEVEL2_DRV_DIR /var/lib/vscp/drivers/level2/)

# Generate position-independent code (-fPIC on UNIX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- System Libraries ---
include(GNUInstallDirs)

set(LIBS_SYSTEM c stdc++)


#   ===========================  cpack  ===========================
IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
  INCLUDE(InstallRequiredSystemLibraries)

  SET(CPACK_SET_DESTDIR ON)
  SET(CPACK_PACKAGING_INSTALL_PREFIX "/var/lib/vscp/drivers")
  SET(CPACK_GENERATOR "DEB" "RPM" "TGZ" "ZIP")

  
  set(CPACK_PACKAGE_NAME ${APP_LOW_NAME})
  set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY ${APP_NAME})


  SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
  SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
#  SET(CPACK_IGNORE_FILES "\\.psd$;/CVS/;/\\.svn/;/\\.git/;\\.swp$;/CMakeLists.txt.user;\\.#;/#;\\.tar.gz$;/CMakeFiles/;CMakeCache.txt;\\.qm$;/build/;\\.diff$;.DS_Store'")
#  set(CPACK_SOURCE_IGNORE_FILES ${CPACK_IGNORE_FILES})

  SET(CPACK_NSIS_INSTALLED_ICON_NAME "${APP_LOW_NAME}.ico")
  SET(CPACK_NSIS_HELP_LINK ${APP_URL})
  SET(CPACK_NSIS_URL_INFO_ABOUT ${APP_URL})


    SET(CPACK_DEBIAN_PACKAGE_DEPENDS " libexpat-dev, libssl-dev ")
    SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    SET(CPACK_DEBIAN_PACKAGE_SECTION "network")
    SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})


  SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)

  # Load packaging facilities.
  INCLUDE(CPack)
 
ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# pthreads
set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#openssl
find_package(OpenSSL REQUIRED)


include(FetchContent)

set(VSCP_FETCH_CONTENT_OPTIONS)
if(NOT CMAKE_VERSION VERSION_LESS "3.18")
  list(APPEND VSCP_FETCH_CONTENT_OPTIONS SOURCE_SUBDIR "__vscp_sources_only__")
endif()
if(NOT CMAKE_VERSION VERSION_LESS "3.24")
  list(APPEND VSCP_FETCH_CONTENT_OPTIONS DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

FetchContent_Declare(
  vscp
  # Only a handful of VSCP source files are compiled directly into vscpd, so
  # there is no need to clone the repository. A pinned source tarball avoids
  # fetching ~1.2GB of git history plus ~400MB of submodules that this project
  # never uses.
  # Get URL_HASH
  # curl -sL https://codeload.github.com/grodansparadis/vscp/tar.gz/<commit> | sha256sum
  URL https://codeload.github.com/grodansparadis/vscp/tar.gz/911239f8fc7a5f084fe3435c6c7f2ee31e9f4c90
  URL_HASH SHA256=a5e1c8154f22139082f857901343580dd510b8fc58c7cfb9d23d6e269cca24fa
  ${VSCP_FETCH_CONTENT_OPTIONS}
)
# Make the VSCP sources available without adding its standalone library targets
# to this build. The daemon compiles only the VSCP source files listed below.
if(CMAKE_VERSION VERSION_LESS "3.18")
  FetchContent_GetProperties(vscp)
  if(NOT vscp_POPULATED)
    FetchContent_Populate(vscp)
  endif()
else()
  FetchContent_MakeAvailable(vscp)
endif()

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
)
FetchContent_MakeAvailable(nlohmann_json)


# Misc defines
#add_definitions(-DDEBUG_TRACE)

set(RESOURCE_FILES
        README.md
        forms/index.html)

# Add files to library
add_library(vscpl2drv-socketcan
  ${CMAKE_SOURCE_DIR}/src/vscpl2drv-socketcan.h
  ${CMAKE_SOURCE_DIR}/src/vscpl2drv-socketcan.cpp
  ${CMAKE_SOURCE_DIR}/src/socketcan.h
  ${CMAKE_SOURCE_DIR}/src/socketcan.cpp
  ${vscp_SOURCE_DIR}/src/vscp/common/guid.h
  ${vscp_SOURCE_DIR}/src/vscp/common/guid.cpp
  ${vscp_SOURCE_DIR}/src/vscp/common/vscphelper.h
  ${vscp_SOURCE_DIR}/src/vscp/common/vscphelper.cpp
) 


include_directories( PUBLIC src/
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${vscp_SOURCE_DIR}/src/common/"
    "${vscp_SOURCE_DIR}/src/vscp/common/"
    "${CMAKE_BINARY_DIR}"
    "${OPENSSL_INCLUDE_DIR}"
    "${spdlog_SOURCE_DIR}/include/"
    "${nlohmann_json_SOURCE_DIR}/include/" )
  


target_link_libraries(vscpl2drv-socketcan PRIVATE     
    m
    dl
    z
    Threads::Threads
    OpenSSL::SSL 
    OpenSSL::Crypto
    spdlog
    nlohmann_json)


# Install

install(TARGETS vscpl2drv-socketcan
          LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_}${VSCP_LEVEL2_DRV_DIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_MANDIR}            
          RESOURCE DESTINATION ${CMAKE_INSTALL_FULL_}/var/lib/vscp/vscpd) 
install(FILES ${CMAKE_SOURCE_DIR}/resources/linux/socketcan.json
          DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/vscpl2drv-socketcan/")      


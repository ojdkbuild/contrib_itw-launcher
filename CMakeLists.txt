# Copyright 2017, akashche at redhat.com
#
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

cmake_minimum_required ( VERSION 2.8.12 )

project ( itw_launcher C CXX )

set ( ${PROJECT_NAME}_ICON_PATH ${openjdk_INSTALLER_RESOURCES_PATH}/icon.ico CACHE STRING "Path to icon file" )
set ( ${PROJECT_NAME}_MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/resources/launcher.manifest CACHE STRING "Path to checker manifest" )

configure_file ( ${CMAKE_CURRENT_LIST_DIR}/resources/launcher.rc
        ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc )
        
add_executable ( javaws WIN32
        src/launcher.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc )
        
target_compile_options ( javaws PRIVATE /W4 /WX )

target_link_libraries ( javaws
        shell32
        ole32
        comctl32
        advapi32 )
        
set_property ( TARGET javaws APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )        
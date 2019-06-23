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

set ( ${PROJECT_NAME}_ICON_PATH "${openjdk_INSTALLER_RESOURCES_PATH}/icon.ico" CACHE STRING "Path to icon file" )
set ( ${PROJECT_NAME}_EXE_VERSION "1,${openjdk_MAJOR_VERSION},${openjdk_UPDATE}${openjdk_RPMBUILD},${openjdk_BUILD}" CACHE STRING "EXE version field" )
set ( ${PROJECT_NAME}_FILE_VERSION "1.${openjdk_MAJOR_VERSION}.0.${openjdk_UPDATE}.${openjdk_RPMBUILD}" CACHE STRING "File version field" )
set ( ${PROJECT_NAME}_COMPANY_NAME_LABEL "${openjdk_VENDOR}" CACHE STRING "Company name version field" )
set ( ${PROJECT_NAME}_FILE_DESCRIPTION_JAVAWS "${openjdk_VENDOR_SHORT} WebStart Launcher" CACHE STRING "Launcher description" )
set ( ${PROJECT_NAME}_PRODUCT_VERSION "${${PROJECT_NAME}_FILE_VERSION}" CACHE STRING "Product version field" )
set ( ${PROJECT_NAME}_MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/resources/launcher.manifest CACHE STRING "Path to launcher manifest" )
set ( ${PROJECT_NAME}_ERROR_DIALOG_TITLE_LABEL "${openjdk_VENDOR_SHORT} WebStart error" CACHE STRING "Error dialog title" )
set ( ${PROJECT_NAME}_BROWSER_ERROR_TEXT_LABEL "Error starting default web-browser" CACHE STRING "Browser start error" )
set ( ${PROJECT_NAME}_ERROR_HELP_URL_LABEL "https://github.com/ojdkbuild/ojdkbuild/wiki/WebStart" CACHE STRING "Help URL" )
set ( ${PROJECT_NAME}_ERROR_DIALOG_HEADER_LABEL "${openjdk_VENDOR_SHORT} WebStart was unable to start Java VM." CACHE STRING "Error dialog header" )
set ( ${PROJECT_NAME}_ERROR_DIALOG_SUBHEADER_LABEL "Please follow the link below for troubleshooting information." CACHE STRING "Error dialog subheader" )
set ( ${PROJECT_NAME}_NO_ARGS_ERROR_HEADER "This application is not intended to be used directly. Please run JNLP from a web-browser or from a file explorer." CACHE STRING "Error header on no arguments given" )
set ( ${PROJECT_NAME}_NO_ARGS_ERROR_LABEL "No arguments specified. Please specify a path (or URL) to JNLP file or a 'jnlp://' URL." CACHE STRING "Error message on no arguments given" )
set ( ${PROJECT_NAME}_MIGRATE_APPDIR_PREFIX "java-1.8.0-openjdk-1.8.0." CACHE STRING "Prefix of the application directory that can be used as a source to migrate old data" )
# test options
set ( ${PROJECT_NAME}_ENABLE_TEST ON CACHE BOOL "Built test app and allow to run a test with it" )

# resources
configure_file ( ${CMAKE_CURRENT_LIST_DIR}/resources/launcher.rc
        ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc )
configure_file ( ${CMAKE_CURRENT_LIST_DIR}/resources/javaws_options.txt
        ${CMAKE_CURRENT_BINARY_DIR}/javaws_options.txt )

# dependencies
ojdkbuild_add_subdirectory ( ${OJDKBUILD_DIR}/contrib/ojdkbuild-utils ojdkbuild_utils )
set ( ${PROJECT_NAME}_DEPS ojdkbuild_utils )
ojdkbuild_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# target
add_executable ( javaws WIN32
        src/launcher.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc )

target_include_directories ( javaws BEFORE PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )

target_compile_options ( javaws PRIVATE /W4 /WX )

target_link_libraries ( javaws
        ojdkbuild_utils
        shell32
        ole32
        comctl32
        advapi32 )
        
set_property ( TARGET javaws APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )

if ( ${PROJECT_NAME}_ENABLE_TEST )

    add_executable ( ${PROJECT_NAME}_test WIN32
            test/launcher_test.cpp )

    target_include_directories ( ${PROJECT_NAME}_test BEFORE PRIVATE
            ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )

    target_link_libraries ( ${PROJECT_NAME}_test
            ojdkbuild_utils
            shell32 )

    add_custom_target ( ${PROJECT_NAME}_test_run
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${PROJECT_NAME}_test_scratch
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_NAME}_test_scratch/jdk
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_NAME}_test_scratch/jdk/jre
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_NAME}_test_scratch/jdk/jre/bin
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_NAME}_test_scratch/jdk/webstart
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/javaws.exe ${PROJECT_NAME}_test_scratch/jdk/webstart/javaws.exe
            COMMAND ${CMAKE_COMMAND} -E copy javaws_options.txt ${PROJECT_NAME}_test_scratch/jdk/webstart/javaws_options.txt
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_test.exe ${PROJECT_NAME}_test_scratch/jdk/jre/bin/java.exe
            COMMAND ${PROJECT_NAME}_test_scratch/jdk/webstart/javaws.exe foo "bar baz"
            DEPENDS javaws ${PROJECT_NAME}_test
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Running launcher test ..." )
endif ( )
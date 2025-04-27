cmake_minimum_required(VERSION 3.10)
project(proot)

# Options
option(BUILD_CARE "Build CARE (Copy and Run) version" ON)
option(BUILD_PYTHON_EXTENSION "Build Python extension" ON)

# Configuration
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Os -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE")

# Version information
set(VERSION "0-0")
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
    find_package(Git)
    if(GIT_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-list --max-count=1 --abbrev-commit HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        set(VERSION "${GIT_VERSION}-${GIT_COMMIT}")
    endif()
endif()

# Check for dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(TALLOC REQUIRED talloc)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(LIBARCHIVE libarchive)

# Check for Python and SWIG if Python extension is enabled
if(BUILD_PYTHON_EXTENSION)
    find_package(Python3 COMPONENTS Development REQUIRED)
    find_package(SWIG REQUIRED)
    include(UseSWIG)
endif()

# Configure build.h
configure_file(
    ${CMAKE_SOURCE_DIR}/build.h.in
    ${CMAKE_BINARY_DIR}/build.h
)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/../lib/uthash/include
    ${CMAKE_BINARY_DIR}  # for generated build.h
    ${TALLOC_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

if(BUILD_PYTHON_EXTENSION)
    include_directories(${Python3_INCLUDE_DIRS})
endif()

# Source files
set(COMMON_SOURCES
    cli/cli.c
    cli/proot.c
    cli/note.c
    execve/enter.c
    execve/exit.c
    execve/shebang.c
    execve/elf.c
    execve/ldso.c
    execve/auxv.c
    execve/aoxp.c
    path/binding.c
    path/glue.c
    path/canon.c
    path/path.c
    path/proc.c
    path/temp.c
    syscall/seccomp.c
    syscall/syscall.c
    syscall/chain.c
    syscall/enter.c
    syscall/exit.c
    syscall/sysnum.c
    syscall/socket.c
    syscall/heap.c
    syscall/rlimit.c
    tracee/tracee.c
    tracee/mem.c
    tracee/reg.c
    tracee/event.c
    ptrace/ptrace.c
    ptrace/user.c
    ptrace/wait.c
    extension/extension.c
    extension/kompat/kompat.c
    extension/fake_id0/fake_id0.c
    extension/fake_id0/fake_id0_db.c
    extension/link2symlink/link2symlink.c
    extension/portmap/portmap.c
    extension/portmap/map.c
    loader/loader.c
    loader/assembly.S
)

set(CARE_SOURCES
    cli/care.c
    cli/care-manual.c
    extension/care/care.c
    extension/care/final.c
    extension/care/extract.c
    extension/care/archive.c
)

# Check for 32-bit loader support
try_compile(HAS_LOADER_32BIT
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/arch.h
)

if(HAS_LOADER_32BIT)
    set(LOADER_32BIT_SOURCES
        loader/loader-m32.c
        loader/assembly-m32.S
    )
endif()

# Python extension sources
if(BUILD_PYTHON_EXTENSION)
    set(PYTHON_EXTENSION_SOURCES
        extension/python/python.c
        extension/python/proot_wrap.c
        extension/python/python_extension.c
        extension/python/proot.c
    )
    
    # Generate SWIG wrapper
    set_source_files_properties(extension/python/proot.i PROPERTIES CPLUSPLUS ON)
    swig_add_library(python_extension
        TYPE MODULE
        LANGUAGE python
        SOURCES extension/python/proot.i
    )
    target_link_libraries(python_extension PRIVATE ${Python3_LIBRARIES})
endif()

# Main proot executable
add_executable(proot ${COMMON_SOURCES})
target_link_libraries(proot
    ${TALLOC_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    m dl z pthread
)

# CARE executable
if(BUILD_CARE)
    add_executable(care ${COMMON_SOURCES} ${CARE_SOURCES})
    target_link_libraries(care
        ${TALLOC_LIBRARIES}
        ${SQLITE3_LIBRARIES}
        ${LIBARCHIVE_LIBRARIES}
        m dl z pthread
    )
endif()

# fakedb2fsconfig tool
add_executable(fakedb2fsconfig cli/fakedb2fsconfig.c)
target_link_libraries(fakedb2fsconfig
    ${TALLOC_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

# Installation
install(TARGETS proot DESTINATION bin)
if(BUILD_CARE)
    install(TARGETS care DESTINATION bin)
endif()
install(TARGETS fakedb2fsconfig DESTINATION bin)
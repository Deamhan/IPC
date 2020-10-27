cmake_minimum_required(VERSION 3.15)

project(IPC)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

enable_testing()

if (NOT WIN32)
    if(CMAKE_COMPILER_IS_GNUCC)
        set(ADDITIONAL_FS_LINK_DEPENDENCIES stdc++fs)
    endif() 
endif()

set(IPC_COMMON_SOURCES source/ipc.cpp)
add_executable(test-message ${IPC_COMMON_SOURCES}
                            tests/test-message.cpp)
if(WIN32)
   target_link_libraries(test-message ws2_32)
else()
    target_link_libraries(test-message pthread 
                                       ${ADDITIONAL_FS_LINK_DEPENDENCIES})
endif()
set_target_properties(test-message PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")
add_test(NAME ipc-test-message COMMAND test-message)
                            
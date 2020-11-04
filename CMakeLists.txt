cmake_minimum_required(VERSION 3.15)

project(IPC)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

enable_testing()

if (WIN32)
    set(IPC_LINK_DEPS ws2_32)
else()
    set(IPC_LINK_DEPS pthread)
    if(CMAKE_COMPILER_IS_GNUCC)
        set(IPC_LINK_DEPS ${IPC_LINK_DEPS}
                          stdc++fs)
    endif() 
endif()

set(IPC_COMMON_SOURCES source/ipc.cpp)

# tests
add_executable(test-message ${IPC_COMMON_SOURCES}
                            tests/test-message.cpp)
target_link_libraries(test-message ${IPC_LINK_DEPS})
set_target_properties(test-message PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")
add_test(NAME ipc-test-message COMMAND test-message)
    
# examples
add_executable(simple-message-client ${IPC_COMMON_SOURCES}
                                     examples/simple-message-client.cpp)
target_link_libraries(simple-message-client ${IPC_LINK_DEPS})
set_target_properties(simple-message-client PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")
                                   
add_executable(simple-message-server ${IPC_COMMON_SOURCES}
                                     examples/simple-message-server.cpp)
target_link_libraries(simple-message-server ${IPC_LINK_DEPS})
set_target_properties(simple-message-server PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")

add_executable(simple-rpc-client ${IPC_COMMON_SOURCES}
                                 examples/simple-rpc-client.cpp)
target_link_libraries(simple-rpc-client ${IPC_LINK_DEPS})
set_target_properties(simple-rpc-client PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")

add_executable(simple-rpc-server ${IPC_COMMON_SOURCES}
                                     examples/simple-rpc-server.cpp)
target_link_libraries(simple-rpc-server ${IPC_LINK_DEPS})
set_target_properties(simple-rpc-server PROPERTIES COMPILE_FLAGS "-D__MSG_USE_TAGS__=1 -D__AFUNIX_H__=1")
                        
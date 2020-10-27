# Introducing to IPC
**IPC** is lightweight cross platform C++ Inter Process Communication library.

## Licence
IPC is distributed under the **MPL v2.0** License. See [LICENSE](http://mozilla.org/MPL/2.0/) for details.

## Library structure
IPC library consists of 4 class types: *sockets*, *messages*, *exceptions* and *RPC*-related classes. *Socket classes* allows user to send and receive either raw data (as *raw* messages) or tuple-like type safe messages. Type safety checking can be disabled for performance reasons, maximum message size can be tuned too. *RPC*-related classes (and *exceptions*) provide easy to use message based facility for remote procedure calls.

## Requirements
Library is written using **C++ 17** standard, so compatible compiler is required. On *Windows* some library features (Unix sockets related classes) may not be available if operating system or *Windows SDK* is not new enough.

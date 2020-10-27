/**
\mainpage Table of Contents
-# \ref README.md
-# \ref page1

\page page1 Message based communication
IPC library provides two inter process communication methods: message exchange and RPC. Second method is implemented as a set of classes that wrap messange exchange to provide more simple way to call remote service function and process callbacks, but it lucks some flexability of message exchange.
This methods can be mixed to archive flexablity and simplicity in the same time. 

To start use of IPC library by message based method include <i>ipc.h</i> to your source and add <i>ipc.cpp</i> to your project (for both server and client). Lets see server side first.

\section server Server application

First of all we must create listening socket, let it be an instance of ipc::UnixServerSocket.

\code{.cpp}
    const char * link = "foo";
    ipc::UnixServerSocket server_socket{ link };
    if (!server_socket.is_ok())
        throw IPCSocketBindException{link};
\endcode

Now we are ready to process incoming connections, but first we will discuss two message classes: ipc::InMessage and ipc::OutMessage. This classes allows us 'out of the box' to serialize several 'primitive' types in stream manner. This 'primitive' types are:
<i>uint32_t, int32_t, uint64_t, int64_t, double, char, ipc::Message::RemotePtr, <b>string type</b> and <b>blob type</b></i>. <b>String type</b> may be any <i>std::string_view</i> compatible type (null termination is not required) for serializing and <i>std::string</i> for deserializing.
<b>Blob type</b> is <i>std::pair<const uint8_t*, size_t></i> for serializing and <i>std::vector<uint8_t></i> or <i>std::pair<std::array<uint8_t, N>size_t></i> for deserializing. To serialize/deserialize custom data structures we should overload stream operators, here is example:

\code{.cpp}
    struct MyStruct
    {
        uint32_t a;
        int32_t  b;
    };

    ipc::InMessage& operator <<(ipc::InMessage& in, const MyStruct& arg)
    {
        return (in << arg.a << arg.b);
    }
    
    ipc::OutMessage& operator >>(ipc::OutMessage& out, const MyStruct& arg)
    {
        return (out >> arg.a >> arg.b);
    }
\endcode

Second part of minimal server application is accept loop:

\code{.cpp}
    while (!stop)
    {
        auto predicate = [stop]() { return !stop; };
        auto p2p = server_socket.accept();
        if (!p2p.is_ok())
            break;
        
        ipc::InMessage in;
        if (!p2p.read_message(in, predicate))
            continue;
        
        std::string req;
        if (!(in >> req).is_ok())
            continue;
        
        ipc::OutMessage out;
        if (!(out << req << " processed").is_ok())
            continue;
        
        if (!p2p.write_message(out, predicate))
            continue;
        
        p2p.wait_for_shutdown(predicate);   
    }
\endcode

That's all about server, lets see client application.

\section clien Client application.
Client application is even more simple. We should connect to server and interract with it:

\code{.cpp}
    const char * link = "foo";
    ipc::UnixClientSocket client_socket{ link };
    if (!client_socket.is_ok())
        throw IPCBadChannelError{ link };
    
    ipc::OutMessage out;
    const char * req_text = "request";
    if (!(out << req_text).is_ok())
        throw ipc::IPCMessageOverflowException{ req_text };
    
    auto predicate = []() { return true; };
    if (!client_socket.write_message(out, predicate))
        throw ipc::IPCChannelWriteException{ "" };
    
    ipc::InMessage in;
    if (!client_socket.read_message(in, predicate))
        throw ipc::IPCChannelReadException{ "" };
    
    std::string resp;
    if (!(in >> resp).is_ok())
        throw ipc::IPCMessageFormatException{ "" };
    
    client_socket.shutdown(); 
\endcode

ipc::UnixClientSocket::shutdown can be skipped, but I still recommend to call it explicitly.

That's all about message based communication for now.
*/

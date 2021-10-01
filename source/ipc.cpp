/**
 * Lightweight inter process communication library
 * Copyright (C) 2020 Pavel Kovalenko 
 *
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include <algorithm>
#include <condition_variable>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string.h>
#include <thread>

#ifdef __unix__
#include <arpa/inet.h>
#include <netdb.h>
#endif 

#include "../include/ipc.hpp"

#ifdef _WIN32
#   include <combaseapi.h>
#elif defined(__linux__)
#   include <linux/vm_sockets.h>
#endif

namespace ipc
{
    static bool init_socket_api() noexcept
    {
#ifdef _WIN32
        struct WSAInit_t
        {
            bool m_ok;
            WSAInit_t()
            {
                WSADATA wsaData;
                int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
                m_ok = (iResult == NO_ERROR);
            }
        };

        static WSAInit_t init;
        return init.m_ok;
#else
        return true;
#endif
    }

    os_socket_engine::os_socket_engine(socket_t s) : m_ok(init_socket_api()), m_socket(s)
    {
        if (!m_ok)
            throw socket_api_failed_exception(get_socket_error(), __FUNCTION_NAME__);
    }

    void os_socket_engine::close() noexcept
    {
        if (m_socket != INVALID_SOCKET)
        {
#ifdef _WIN32
            closesocket(m_socket);
#else
            ::close(m_socket);
#endif
            m_socket = INVALID_SOCKET;
            m_ok = false;
        }
    }

    void os_point_to_point_socket_engine::shutdown()
    {
        ::shutdown(m_socket, SD_SEND);
        m_ok = false;
    }

    static bool set_non_blocking_mode(socket_t s) noexcept
    {
#ifdef _WIN32
        u_long iMode = 1;
        return (ioctlsocket(s, FIONBIO, &iMode) == NO_ERROR);
#else
        int flags = fcntl(s, F_GETFL);
        return (fcntl(s, F_SETFL, flags | O_NONBLOCK) >= 0);
#endif
    }

    void os_server_socket_engine::bind_proc(const sockaddr* address, size_t size)
    {
        if (INVALID_SOCKET == m_socket)
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to allocate socket");

        if (!set_non_blocking_mode(m_socket))
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to enable non blocking mode");

        if (bind(m_socket, address, size) != 0)
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to bind socket");

        if (listen(m_socket, 100) != 0)
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to listen socket");
    }

    tcp_server_socket_engine::tcp_server_socket_engine(uint16_t port) : os_server_socket_engine(INVALID_SOCKET)
    {
        sockaddr_in serv_addr = {};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        bind_proc((const sockaddr*)&serv_addr, sizeof(serv_addr));
    }

#ifdef __AFUNIX_H__
#   ifdef _WIN32
    static inline bool is_socket_exists(const char* s) noexcept
    {
        return (GetFileAttributesA(s) != INVALID_FILE_ATTRIBUTES);
    }
#   else
    static inline bool is_socket_exists(const char* s) noexcept
    {
        std::error_code ec;
        return std::filesystem::exists(s, ec);
    }
#   endif

    unix_server_socket_engine::unix_server_socket_engine(std::string_view socket_link) : os_server_socket_engine(INVALID_SOCKET), m_link(socket_link)
    {
        sockaddr_un serv_addr;
        serv_addr.sun_family = AF_UNIX;
        strcpy(serv_addr.sun_path, m_link.c_str());

        m_socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
        bind_proc((const sockaddr*)&serv_addr, offsetof(sockaddr_un, sun_path) + strlen(serv_addr.sun_path));
    }

    void unix_server_socket_engine::close() noexcept
    {
        super::close();
        if (!m_link.empty())
            unlink(m_link.c_str());
    }

    unix_client_socket_engine::unix_client_socket_engine(std::string_view path) : client_socket_engine(INVALID_SOCKET)
    {
        if (!is_socket_exists(path.data()))
        {
#   ifdef _WIN32
            int ecode = ERROR_FILE_NOT_FOUND;
#   else
            int ecode = ENOENT;
#   endif
            fail_status<active_socket_prepare_exception>(m_ok, ecode, std::string(__FUNCTION_NAME__) + ": target does not exist");
        }

        sockaddr_un serv_addr = {};
        serv_addr.sun_family = AF_UNIX;
        strncpy(serv_addr.sun_path, path.data(), std::min<size_t>(sizeof(serv_addr.sun_path), path.size()));

        m_socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
        connect_proc((const sockaddr*)&serv_addr, offsetof(sockaddr_un, sun_path) + path.size());
    }

#endif // __AFUNIX_H__

#ifdef __VSOCK__
#   if defined(_WIN32)
    const int HV_PROTOCOL_RAW = 1;
    struct SOCKADDR_HV
    {
        ADDRESS_FAMILY Family;
        USHORT Reserved;
        GUID VmId;
        GUID ServiceId;
    };

    virtual_server_socket_engine::virtual_server_socket_engine(const wchar_t* vm_id_guid, const wchar_t* service_id_guid) : os_server_socket_engine(INVALID_SOCKET)
    {
        SOCKADDR_HV serv_addr = {};

        GUID vm_id = {}, service_id = {};
        if (CLSIDFromString(vm_id_guid, &vm_id) != S_OK || CLSIDFromString(service_id_guid, &service_id) != S_OK)
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to translate CLSIDs");

        serv_addr.Family = AF_HYPERV;
        serv_addr.VmId = vm_id;
        serv_addr.ServiceId = service_id;

        int socket_family = AF_HYPERV;
        int protocol = HV_PROTOCOL_RAW;
#   elif defined(__linux__)
    virtual_server_socket_engine::virtual_server_socket_engine(unsigned cid, unsigned port) : os_server_socket_engine(INVALID_SOCKET)
    {
        int socket_family = AF_VSOCK;
        int protocol = 0;

        sockaddr_vm serv_addr = {};
        serv_addr.svm_family = AF_VSOCK;
        serv_addr.svm_cid = cid;
        serv_addr.svm_port = port;
#   endif

        m_socket = ::socket(socket_family, SOCK_STREAM, protocol);
        bind_proc((const sockaddr*)&serv_addr, sizeof(serv_addr));
    }

#   if defined(_WIN32)
    virtual_client_socket_engine::virtual_client_socket_engine(const wchar_t* vm_id_guid, const wchar_t* service_id_guid) : client_socket_engine(INVALID_SOCKET)
    {
        SOCKADDR_HV serv_addr = {};

        GUID vm_id = {}, service_id = {};
        if (CLSIDFromString(vm_id_guid, &vm_id) != S_OK || CLSIDFromString(service_id_guid, &service_id) != S_OK)
            fail_status<passive_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to translate CLSIDs");

        serv_addr.Family = AF_HYPERV;
        serv_addr.VmId = vm_id;
        serv_addr.ServiceId = service_id;

        int socket_family = AF_HYPERV;
        int protocol = HV_PROTOCOL_RAW;
#   elif defined(__linux__)
    virtual_client_socket_engine::virtual_client_socket_engine(unsigned cid, unsigned port) : client_socket_engine(INVALID_SOCKET)
    {
        int socket_family = AF_VSOCK;
        int protocol = 0;

        sockaddr_vm serv_addr = {};
        serv_addr.svm_family = AF_VSOCK;
        serv_addr.svm_cid = cid;
        serv_addr.svm_port = port;
#   endif

        m_socket = ::socket(socket_family, SOCK_STREAM, protocol);
        connect_proc((const sockaddr*)&serv_addr, sizeof(serv_addr));
    }
#endif // __VSOCK__

    void client_socket_engine::connect_proc(const sockaddr* address, size_t size)
    {
        if (INVALID_SOCKET == m_socket)
            fail_status<active_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to allocate socket");

        const int max_attempts_count = 10;
        int attempt = 0;
        for (; attempt < max_attempts_count && connect(m_socket, address, size) < 0; ++attempt)
        {
            int err_code = get_socket_error();
#ifdef _WIN32
            if (err_code == WSAECONNREFUSED)
#else
            if (err_code == EAGAIN || err_code == ECONNREFUSED || err_code == EINPROGRESS)
#endif
            {
                std::this_thread::sleep_for(std::chrono::seconds(1)); // TODO: fix me
            }
            else
                fail_status<active_socket_prepare_exception>(m_ok, err_code, std::string(__FUNCTION_NAME__) + ": unable to connect");
        }

        if (attempt == max_attempts_count)
            fail_status<active_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to connect");

        if (!set_non_blocking_mode(m_socket))
            fail_status<active_socket_prepare_exception>(m_ok, get_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to enable non blocking mode");
    }

    void tcp_client_socket_engine::connect_proc(uint32_t address, uint16_t port)
    {
        sockaddr_in serv_addr = {};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = htonl(address);

        m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        super::connect_proc((const sockaddr*)&serv_addr, sizeof(serv_addr));
    }

    tcp_client_socket_engine::tcp_client_socket_engine(uint32_t address, uint16_t port) : client_socket_engine(INVALID_SOCKET)
    {
        connect_proc(address, port);
    }

#ifdef _WIN32
    static inline int get_h_socket_error() noexcept { return WSAGetLastError(); }
#else
    static inline int get_h_socket_error() noexcept { return h_errno; }
#endif // _WIN32

    tcp_client_socket_engine::tcp_client_socket_engine(std::string_view address, uint16_t port) : client_socket_engine(INVALID_SOCKET)
    {
        auto info = gethostbyname(address.data());
        if (info == nullptr)
            fail_status<name_to_address_translation_exception>(m_ok, get_h_socket_error(), std::string(__FUNCTION_NAME__) + ": unable to get information about host");
            
        if (info->h_addrtype != AF_INET || info->h_addr_list[0] == nullptr)
            fail_status<bad_hostname_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": unable to get information about host IP address");

        connect_proc(ntohl(*(u_long*)info->h_addr_list[0]), port);
    }

    [[noreturn]] void throw_message_overflow_exception(const char* func_name, size_t req_size, size_t total_size)
    {
        std::string msg(func_name);
        msg.append(": required space ").append(std::to_string(req_size));
        msg.append("exceeds limit of ").append(std::to_string(total_size)).append(" bytes");
        throw message_overflow_exception(std::move(msg));
    }

    [[noreturn]] void throw_type_mismatch_exception(const char* func_name, const char* tag, const char* expected)
    {
        std::string msg(func_name);
        msg.append(": data type mismatch (got ").append(tag).append(", expect ").append(expected).append(")");
        throw type_mismach_exception(std::move(msg));
    }

    [[noreturn]] void throw_message_too_short_exception(const char* func_name, size_t req_size, size_t total_size)
    {
        std::string msg(func_name);
        msg.append(": required space ").append(std::to_string(req_size));
        msg.append(" exceeds message length of ").append(std::to_string(total_size)).append(" bytes");
        throw message_too_short_exception(std::move(msg));
    }

    [[noreturn]] void throw_container_overflow_exception(const char* func_name, size_t req_size, size_t total_size)
    {
        std::string msg(func_name);
        msg.append(": required space ").append(std::to_string(req_size));
        msg.append("exceeds container limit of ").append(std::to_string(total_size)).append(" bytes");
        throw container_overflow_exception(std::move(msg));
    }

#if __MSG_USE_TAGS__
    const char* ipc::message::to_string(type_tag t) noexcept
    {
        switch (t)
        {
        case ipc::message::type_tag::u32:
            return "u32";
        case ipc::message::type_tag::i32:
            return "i32";
        case ipc::message::type_tag::u64:
            return "u64";
        case ipc::message::type_tag::i64:
            return "i64";
        case ipc::message::type_tag::fp64:
            return "fp64";
        case ipc::message::type_tag::str:
            return "str";
        case ipc::message::type_tag::chr:
            return "chr";
        case ipc::message::type_tag::remote_ptr:
            return "remote_ptr";
        case ipc::message::type_tag::blob:
            return "blob";
        default:
            return "unknown";
        }
    }
#endif // __MSG_USE_TAGS__

    out_message& out_message::operator << (const std::string_view& s)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

#if __MSG_USE_TAGS__
        const size_t delta = 2; // terminating '\0' and tag
#else
        const size_t delta = 1; // terminating '\0' only
#endif // __MSG_USE_TAGS__
        const char* arg = s.data();
        const size_t len = s.length();
        const size_t used = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
        const size_t new_used = used + len + delta;
        if (new_used > get_max_size())
            fail_status(throw_message_overflow_exception, m_ok, __FUNCTION_NAME__, new_used, get_max_size());
        else
        {
#if __MSG_USE_TAGS__
            m_buffer.push_back((char)type_tag::str);
#endif // __MSG_USE_TAGS__
            m_buffer.insert(m_buffer.end(), arg, arg + len);
            m_buffer.push_back('\0'); // string_view is not necessarily null terminated, so we set it explicitly
            *(__MSG_LENGTH_TYPE__*)m_buffer.data() += (__MSG_LENGTH_TYPE__)new_used;
        }
        
        return *this;
    }

    out_message& out_message::operator << (const std::pair<const uint8_t*, size_t>& blob)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

#if __MSG_USE_TAGS__
        const size_t delta = 1;
#else
        const size_t delta = 0;
#endif // __MSG_USE_TAGS__
        const uint8_t* arg = blob.first;
        const size_t len = blob.second;
        const size_t used = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
        const size_t new_used = used + len + delta;
        if (new_used > get_max_size())
            fail_status(throw_message_overflow_exception, m_ok, __FUNCTION_NAME__, new_used, get_max_size());
        else
        {
#if __MSG_USE_TAGS__
            m_buffer.push_back((char)type_tag::blob);
#endif // __MSG_USE_TAGS__
            const __MSG_LENGTH_TYPE__ blob_len = (__MSG_LENGTH_TYPE__)len;
            m_buffer.insert(m_buffer.end(), (const char*)&blob_len, (const char*)(&blob_len + 1));
            m_buffer.insert(m_buffer.end(), arg, arg + len);
            *(__MSG_LENGTH_TYPE__*)m_buffer.data() += (__MSG_LENGTH_TYPE__)new_used;
        }

        return *this;
    }

    in_message& in_message::operator >> (std::string& arg)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

        arg.clear();
        __MSG_LENGTH_TYPE__ size = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
#if __MSG_USE_TAGS__
        const size_t delta = 2; /*termination '\0' and type tag*/
#else
        const size_t delta = 1; /*termination '\0' only*/
#endif // __MSG_USE_TAGS__
        if (size < m_offset + delta)
            fail_status(throw_message_too_short_exception, m_ok, __FUNCTION_NAME__, m_offset + delta, size);

#if __MSG_USE_TAGS__
        type_tag tag = (type_tag)m_buffer[m_offset];
        if (tag != type_tag::str)
            fail_status(throw_type_mismatch_exception, m_ok, __FUNCTION_NAME__, to_string(tag), to_string(type_tag::str));

        ++m_offset;
#endif // __MSG_USE_TAGS__

        const char* begin = &m_buffer[m_offset];
        const char* end = (const char*)memchr(begin, 0, size - m_offset);
        if (end == nullptr)
        {
            m_ok = false;
            std::string msg(__FUNCTION_NAME__);
            msg.append(": terminating zero not found");
            throw container_overflow_exception(std::move(msg));
        }

        arg.assign(begin, end - begin);
        m_offset += arg.length() + 1;

        return *this;
    }

    in_message& in_message::operator >> (std::vector<uint8_t>& blob)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

        __MSG_LENGTH_TYPE__ size = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
#if __MSG_USE_TAGS__
        const size_t delta = 1 + sizeof(__MSG_LENGTH_TYPE__);
#else
        const size_t delta = sizeof(__MSG_LENGTH_TYPE__);
#endif // __MSG_USE_TAGS__
        if (size < m_offset + delta)
            fail_status(throw_message_too_short_exception, m_ok, __FUNCTION_NAME__, m_offset + delta, size);

#if __MSG_USE_TAGS__
        type_tag tag = (type_tag)m_buffer[m_offset];
        if (tag != type_tag::blob)
            fail_status(throw_type_mismatch_exception, m_ok, __FUNCTION_NAME__, to_string(tag), to_string(type_tag::blob));

        ++m_offset;
#endif // __MSG_USE_TAGS__

        const __MSG_LENGTH_TYPE__ blob_len = *(const __MSG_LENGTH_TYPE__*)&m_buffer[m_offset];
        m_offset += sizeof(__MSG_LENGTH_TYPE__);

        if (size < m_offset + blob_len)
            fail_status(throw_message_too_short_exception, m_ok, __FUNCTION_NAME__, m_offset + blob_len, size);

        if (blob_len != 0)
        {
            blob.resize(blob_len);
            memcpy(blob.data(), &m_buffer[m_offset], blob_len);
            m_offset += blob_len;
        }

        return *this;
    }

#if defined(_WIN32) && defined(USE_ALPC)
    Ntdll::Ntdll() noexcept
    {
        auto h_ntdll = GetModuleHandleA("ntdll");
        NtAlpcCreatePort = (NtAlpcCreatePort_t)GetProcAddress(h_ntdll, "NtAlpcCreatePort");
        RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(h_ntdll, "RtlInitUnicodeString");
        NtAlpcSendWaitReceivePort = (NtAlpcSendWaitReceivePort_t)GetProcAddress(h_ntdll, "NtAlpcSendWaitReceivePort");
        NtAlpcAcceptConnectPort = (NtAlpcAcceptConnectPort_t)GetProcAddress(h_ntdll, "NtAlpcAcceptConnectPort");
        AlpcInitializeMessageAttribute = (AlpcInitializeMessageAttribute_t)GetProcAddress(h_ntdll, "AlpcInitializeMessageAttribute");
        AlpcGetMessageAttribute = (AlpcGetMessageAttribute_t)GetProcAddress(h_ntdll, "AlpcGetMessageAttribute");
        NtAlpcConnectPort = (NtAlpcConnectPort_t)GetProcAddress(h_ntdll, "NtAlpcConnectPort");
        RtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(h_ntdll, "RtlNtStatusToDosError");
        AlpcRegisterCompletionList = (AlpcRegisterCompletionList_t)GetProcAddress(h_ntdll, "AlpcRegisterCompletionList");
        NtAlpcSetInformation = (NtAlpcSetInformation_t)GetProcAddress(h_ntdll, "NtAlpcSetInformation");
        NtAlpcCancelMessage = (NtAlpcCancelMessage_t)GetProcAddress(h_ntdll, "NtAlpcCancelMessage");
    }

    Ntdll ntdll;

    alpc_server_engine::alpc_server_engine(const wchar_t* port_name) : alpc_engine(nullptr), m_buffer(msg_max_length + sizeof(PORT_MESSAGE)), m_stop_signal(false)
    {
        UNICODE_STRING us;
        ntdll.RtlInitUnicodeString(&us, port_name);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, 0, nullptr, nullptr);

        ALPC_PORT_ATTRIBUTES server_port_attributes = {};
        server_port_attributes.MaxMessageLength = /*m_buffer.size()*/65000;

        auto status = ntdll.NtAlpcCreatePort(&m_alpc_port, &oa, &server_port_attributes);
        if (!NT_SUCCESS(status))
            fail_status<passive_socket_prepare_exception>(m_ok, ntdll.RtlNtStatusToDosError(status), std::string(__FUNCTION_NAME__) + ": unable to create ALPC port");

        SIZE_T req = 0;
        status = ntdll.AlpcInitializeMessageAttribute(ALPC_MESSAGE_CONTEXT_ATTRIBUTE, (PALPC_MESSAGE_ATTRIBUTES)m_attr_buffer, sizeof(m_attr_buffer), &req);
        if (!NT_SUCCESS(status))
            fail_status<passive_socket_prepare_exception>(m_ok, ntdll.RtlNtStatusToDosError(status), std::string(__FUNCTION_NAME__) + ": unable to initialize message attributes");

        m_listener = std::thread(&alpc_server_engine::listen_proc, this);
    }

    void alpc_server_engine::listen_proc()
    {
        PPORT_MESSAGE msg = (PPORT_MESSAGE)m_buffer.data();
        auto attr = (PALPC_MESSAGE_ATTRIBUTES)m_attr_buffer;
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000; // 1 second (negative means relative timeout)

        while (true)
        {
            SIZE_T len = m_buffer.size();
            auto status = ntdll.NtAlpcSendWaitReceivePort(m_alpc_port, 0, nullptr, nullptr, msg, &len, attr, &timeout);

            if (!NT_SUCCESS(status))
                return;

            if (status == STATUS_TIMEOUT)
            {
                if (!m_stop_signal.load(std::memory_order_relaxed))
                    continue;

                break;
            }

            switch (msg->u2.s2.Type & LPC_MESSAGE_TYPE)
            {
            case LPC_CONNECTION_REQUEST:
            {
                HANDLE h = nullptr;
                auto id = msg->MessageId;
                memset(msg, 0, sizeof(PORT_MESSAGE));
                msg->u1.s1.DataLength = 0;
                msg->u1.s1.TotalLength = sizeof(PORT_MESSAGE);
                msg->MessageId = id;
                if (!m_accept_slot.try_push(msg))
                    ntdll.NtAlpcAcceptConnectPort(&m_alpc_port, &h, 0, nullptr, nullptr, nullptr, msg, nullptr, FALSE);

                break;
            }
            case LPC_CLIENT_DIED:
            case LPC_PORT_CLOSED:
            case LPC_REQUEST:
            {
                alpc_connection* connection = *(alpc_connection**)ntdll.AlpcGetMessageAttribute(attr, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
                connection->m_slot.push_with_exception_saving(msg);
                break;
            }
            default:
                break;
            }
        }
    }

    alpc_server_engine::~alpc_server_engine()
    {
        m_stop_signal = true;
        m_listener.join();
    }

    alpc_client_engine::alpc_client_engine(const wchar_t* port_name) : alpc_point_to_point_connection_engine(nullptr), m_buffer(msg_max_length + sizeof(PORT_MESSAGE))
    {
        UNICODE_STRING us;
        ntdll.RtlInitUnicodeString(&us, port_name);

        auto status = ntdll.NtAlpcConnectPort(&m_alpc_port, &us, nullptr, nullptr, ALPC_MSGFLG_SYNC_REQUEST, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!NT_SUCCESS(status))
            fail_status<active_socket_prepare_exception>(m_ok, ntdll.RtlNtStatusToDosError(status), std::string(__FUNCTION_NAME__) + ": unable to connect");
    }

    void alpc_engine::close() noexcept
    {
        if (m_alpc_port != nullptr)
            CloseHandle(m_alpc_port);

        m_alpc_port = nullptr;
        m_ok = false;
    }

    DWORD CALLBACK io_job(void* context)
    {
        auto ctx = (io_ctx*)context;
        SIZE_T len = ctx->resp_max_len;
        ctx->promise.set_value(ntdll.NtAlpcSendWaitReceivePort(ctx->alpc_port, 0x18, ctx->msg, nullptr, ctx->msg, &len, nullptr, nullptr));

        return 0;
    }
#endif // _WIN32 || USE_ALPC
}

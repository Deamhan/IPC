/**
 * Lightweight inter process communication library
 * Copyright (C) 2020 Pavel Kovalenko 
 *
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

/*
    Template methods (rpc.h) implementations. It shouldn't be used directly.
*/

#pragma once

#include "../include/ipc.hpp"

#include <future>

#ifndef __FUNCTION_NAME__
#ifdef __GNUG__ 
#define __FUNCTION_NAME__   __PRETTY_FUNCTION__
#elif defined (_WIN32)
#define __FUNCTION_NAME__   __FUNCTION__ 
#else
#define __FUNCTION_NAME__   __func__
#endif
#endif

namespace ipc
{  
    template<bool Reading, typename Predicate>
    static bool wait_for(socket_t s, const Predicate& predicate, uint16_t timeout_sec)
    {
        int count = 0;
        while (count == 0)
        {
            if (!predicate())
                throw user_stop_request_exception(__FUNCTION_NAME__);

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            timeval timeout = { timeout_sec, 0 };
            if constexpr (Reading)
                count = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
            else
                count = select(FD_SETSIZE, nullptr, &fds, nullptr, &timeout);
        };

        return (count >= 0);
    }

    template<typename callable_t, typename... Args>
    [[noreturn]] static void fail_status(callable_t& c, bool& status, Args&&... args)
    {
        status = false;
        c(std::forward<Args>(args)...);
        throw std::logic_error(std::string("Implementation internal error (noreturn is required): ") + __FUNCTION_NAME__);
    }

    template <typename exception_t, typename... Args>
    [[noreturn]] static inline void fail_status(bool& status, Args&&... args)
    {
        status = false;
        throw exception_t(std::forward<Args>(args)...);
    }

#ifdef _WIN32
    static inline int get_socket_error() noexcept { return WSAGetLastError(); }
#else
    static inline int get_socket_error() noexcept { return errno; }
#endif

    template<typename Predicate>
    socket_t os_server_socket_engine::accept(const Predicate& predicate, uint16_t timeout_sec)
    {
        std::lock_guard<std::mutex> lm(m_lock);
        do
        {
            if (!wait_for<true>(m_socket, predicate, timeout_sec))
                fail_status<socket_accept_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);

#ifdef __linux__
            socket_t p2p_socket = ::accept4(m_socket, nullptr, 0, SOCK_NONBLOCK);
#else
            socket_t p2p_socket = ::accept(m_socket, nullptr, 0);
#endif
            if (p2p_socket == INVALID_SOCKET)
            {
                int err_code = get_socket_error();
#ifdef _WIN32
                if (err_code == WSAEWOULDBLOCK)
#else
                if (err_code == EAGAIN || err_code == EWOULDBLOCK)
#endif
                    continue;
                else
                    throw socket_accept_exception(err_code, __FUNCTION_NAME__);
            }
            else
                return p2p_socket;
        } while (true);
    }

    template<typename Predicate>
    inline void os_point_to_point_socket_engine::wait_for_shutdown(const Predicate& predicate, uint16_t timeout_sec)
    {
        if (!wait_for<true>(m_socket, predicate, timeout_sec))
            fail_status<socket_read_exception>(m_ok, 0, __FUNCTION_NAME__);
    }

    template<typename Predicate>
    size_t os_point_to_point_socket_engine::read(char* message, size_t size, const Predicate& predicate, uint16_t timeout_sec)
    {
        size_t read = 0;
        size_t msg_size = std::numeric_limits<size_t>::max();
        while (read < size)
        {
            if (!wait_for<true>(m_socket, predicate, timeout_sec))
                fail_status<socket_read_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);

            int result = recv(m_socket, message + read, size - read, 0);
            if (result < 0)
            {
#ifdef __unix__
                if (get_socket_error() == EAGAIN)
                    continue;
#endif

                fail_status<socket_read_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);
            }
            else if (result != 0)
            {
                read += (uint32_t)result;
                if (msg_size == std::numeric_limits<size_t>::max() && read >= sizeof(__MSG_LENGTH_TYPE__))
                {
                    msg_size = *(__MSG_LENGTH_TYPE__*)message;
                    size = std::min<size_t>(size, msg_size);
                }
            }
            else
                break;
        }

        return read;
    }

    template<typename Predicate>
    bool os_point_to_point_socket_engine::write(const char* message, const Predicate& predicate, uint16_t timeout_sec)
    {
        do
        {
            if (!wait_for<false>(m_socket, predicate, timeout_sec))
                fail_status<socket_write_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);

            int result = send(m_socket, message, *(const __MSG_LENGTH_TYPE__*)message, 0);
            if (result >= 0)
                return true;
            else
            {
                const int err = get_socket_error();
#ifdef _WIN32
                if (err == WSAEWOULDBLOCK)
#else
                if (err == EAGAIN || err == EWOULDBLOCK)
#endif
                    continue;

                fail_status<socket_write_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);
            }
        } while (true);
    }
    
    template <class Engine> template<typename Predicate>
    inline server_data_socket<typename Engine::point_to_point_engine_t> server_socket<Engine>::accept(const Predicate& predicate)
    {
        return server_data_socket<typename Engine::point_to_point_engine_t>(this->m_engine.accept(predicate, 1));
    }
    
    template <typename exception_t, typename... Args>
    static inline void check_status(bool status, Args&&... args)
    {
        if (!status)
            throw exception_t(std::forward<Args>(args)...);
    }

    template <typename exception_t, typename... Args>
    static inline bool update_status(bool& status, bool new_status, Args&&... args)
    {
        status = new_status;
        check_status<exception_t>(status, std::forward<Args>(args)...);
        return true;
    }

    template <class Engine> template<typename Predicate>
    inline void server_data_socket<Engine>::get_request(std::vector<char>& message, const Predicate& predicate)
    {
        check_status<bad_socket_exception>(this->m_engine.is_ok(), __FUNCTION_NAME__);

        size_t read = this->m_engine.read(message.data(), message.size(), predicate, 1);
        bool ok = false;
        if (read >= sizeof(__MSG_LENGTH_TYPE__))
        {
            auto size = *(__MSG_LENGTH_TYPE__*)message.data();
            ok = (read == size);
        }

        update_status<validation_error>(this->m_engine.is_ok(), ok, __FUNCTION_NAME__);
    }
    
    template <class Engine> template<typename Predicate>
    inline void server_data_socket<Engine>::send_response(const char* message, const Predicate& predicate)
    {
        check_status<bad_socket_exception>(this->m_engine.is_ok(), __FUNCTION_NAME__);

        this->m_engine.write(message, predicate, 1);
    }

    template <class Engine> template<typename Predicate>
    inline void client_socket<Engine>::send_request(const char * request, std::vector<char>& response, const Predicate& predicate)
    {
        this->m_engine.send_request(request, response.data(), response.size(), predicate, 1);
    }

    template <class Engine> template<typename Predicate>
    inline void client_socket<Engine>::send_request(out_message& request, in_message& response, const Predicate& predicate)
    {
        try
        {
            class request_cleaner
            {
                out_message& m_request;
            public:
                request_cleaner(out_message& request) noexcept : m_request(request) {}
                ~request_cleaner() { m_request.clear(); }
            } cleaner(request);

            response.clear();
            send_request(request.get_data().data(), response.get_data(), predicate);
        }
        catch (...)
        {
            response.clear();
            throw;
        } 
    }

    template <>
    struct message::tag_traits<uint32_t>
    {
        static const message::type_tag value = message::type_tag::u32;
    };
    
    template <>
    struct message::tag_traits<int32_t>
    {
        static const message::type_tag value = message::type_tag::i32;
    };
    
    template <>
    struct message::tag_traits<int64_t>
    {
        static const message::type_tag value = message::type_tag::i64;
    };
    
    template <>
    struct message::tag_traits<uint64_t>
    {
        static const message::type_tag value = message::type_tag::u64;
    };
    
    template <>
    struct message::tag_traits<double>
    {
        static const message::type_tag value = message::type_tag::fp64;
    };
    
    
    template <>
    struct message::tag_traits<const char*>
    {
        static const message::type_tag value = message::type_tag::str;
    };
    
    template <>
    struct message::tag_traits<std::string>
    {
        static const message::type_tag value = message::type_tag::str;
    };
    
    template <>
    struct message::tag_traits<char>
    {
        static const message::type_tag value = message::type_tag::chr;
    };
    
    template <>
    struct message::tag_traits<message::remote_ptr<false>>
    {
        static const message::type_tag value = message::type_tag::remote_ptr;
    };

    template <>
    struct message::tag_traits<message::remote_ptr<true>>
    {
        static const message::type_tag value = message::type_tag::const_remote_ptr;
    };

    [[noreturn]] void throw_message_overflow_exception(const char* func_name, size_t req_size, size_t total_size);
    [[noreturn]] void throw_type_mismatch_exception(const char* func_name, const char* tag, const char* expected);
    [[noreturn]] void throw_message_too_short_exception(const char* func_name, size_t req_size, size_t total_size);
    [[noreturn]] void throw_container_overflow_exception(const char* func_name, size_t req_size, size_t total_size);

    template <message::type_tag Tag, typename T, typename>
    inline out_message& out_message::push(T arg)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

    #if __MSG_USE_TAGS__
        const size_t delta = 1;
    #else
        const size_t delta = 0;
    #endif // __MSG_USE_TAGS__
        size_t used = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
        size_t new_used = used + sizeof(T) + delta;
        if (new_used > get_max_size())
            fail_status(throw_message_overflow_exception, m_ok, __FUNCTION_NAME__, new_used, get_max_size());
    
    #if __MSG_USE_TAGS__
        m_buffer.push_back((char)Tag);
    #endif // __MSG_USE_TAGS__
        const char* data = (const char*)&arg;
        m_buffer.insert(m_buffer.end(), data, data + sizeof(T));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = (__MSG_LENGTH_TYPE__)new_used;
    
        return *this;
    }
    
    inline void out_message::clear() noexcept
    {
        m_buffer.resize(sizeof(__MSG_LENGTH_TYPE__));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
    }
    
    inline void in_message::clear() noexcept
    {
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
        m_offset = sizeof(__MSG_LENGTH_TYPE__);
    }

#if __MSG_USE_TAGS__
    inline constexpr bool message::is_compatible_tags(type_tag source, type_tag target) noexcept
    {
        if (source == target)
            return true;

        return  (target == type_tag::const_remote_ptr && source == type_tag::remote_ptr);
    }
#endif // __MSG_USE_TAGS__

    template <message::type_tag Expected_tag, typename T, typename>
    inline in_message& in_message::pop(T& arg)
    {
        check_status<bad_message_exception>(m_ok, std::string(__FUNCTION_NAME__) + ": fail flag is set");

#if __MSG_USE_TAGS__
        const size_t delta = 1;
#else
        const size_t delta = 0;
#endif // __MSG_USE_TAGS__

        const size_t size = *(const __MSG_LENGTH_TYPE__*)m_buffer.data();
        size_t new_offset = m_offset + sizeof(T) + delta;
        if (size < new_offset)
            fail_status(throw_message_too_short_exception, m_ok, __FUNCTION_NAME__, new_offset, size);
        else
        {
#if __MSG_USE_TAGS__
            message::type_tag tag = (message::type_tag)m_buffer[m_offset];
            if (!is_compatible_tags(tag, Expected_tag))
                fail_status(throw_type_mismatch_exception, m_ok, __FUNCTION_NAME__, to_string(tag), to_string(Expected_tag));

            ++m_offset;
#endif // __MSG_USE_TAGS__
            arg = *(T*)&m_buffer[m_offset];
            m_offset = new_offset;
        }
    
        return *this;
    }
    
    template <class Engine> template<class Predicate>
    inline void server_data_socket<Engine>::get_request(in_message& message, const Predicate& predicate)
    {
        message.clear();
        try
        {
            get_request(message.get_data(), predicate);
        }
        catch (...)
        {
            message.clear();
            throw;
        }
    }
    
    template <size_t N>
    inline in_message& in_message::operator >> (std::pair<std::array<uint8_t, N>, size_t>& blob)
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

        if (blob_len > N)
            fail_status(throw_container_overflow_exception, m_ok, __FUNCTION_NAME__, blob_len, N);

        if (blob_len != 0)
        {
            memcpy(blob.first.data(), &m_buffer[m_offset], blob_len);
            m_offset += blob_len;
        }

        blob.second = blob_len;
    
        return *this;
    }

#if defined(_WIN32) && defined(USE_ALPC)

    struct Ntdll
    {
        NtAlpcCreatePort_t NtAlpcCreatePort;
        RtlInitUnicodeString_t RtlInitUnicodeString;
        NtAlpcSendWaitReceivePort_t NtAlpcSendWaitReceivePort;
        NtAlpcAcceptConnectPort_t NtAlpcAcceptConnectPort;
        AlpcInitializeMessageAttribute_t AlpcInitializeMessageAttribute;
        AlpcGetMessageAttribute_t AlpcGetMessageAttribute;
        NtAlpcConnectPort_t NtAlpcConnectPort;
        RtlNtStatusToDosError_t RtlNtStatusToDosError;
        AlpcRegisterCompletionList_t AlpcRegisterCompletionList;
        NtAlpcSetInformation_t NtAlpcSetInformation;
        NtAlpcCancelMessage_t NtAlpcCancelMessage;

        Ntdll() noexcept;
    };

    extern Ntdll ntdll;

    inline void blocking_slot::push(PPORT_MESSAGE msg, std::unique_lock<std::mutex>& lm)
    {
        if (msg->u1.s1.TotalLength > m_buffer.size())
            throw container_overflow_exception(__FUNCTION_NAME__);

        m_push_cv.wait(lm, [this]() noexcept { return m_push_flag; });
        memcpy(m_buffer.data(), msg, msg->u1.s1.TotalLength);
        m_push_flag = false;
        m_pop_flag = true;
        m_pop_cv.notify_one();
    }

    inline void blocking_slot::push(PPORT_MESSAGE msg)
    {
        std::unique_lock<std::mutex> lm(m_lock);
        push(msg, lm);
    }

    inline bool blocking_slot::try_push(PPORT_MESSAGE msg)
    {
        std::unique_lock<std::mutex> lm(m_lock);
        if (m_push_flag)
        {
            push(msg, lm);
            return true;
        }
        else
            return false;
    }

    inline bool blocking_slot::pop(char* buffer, size_t size, uint32_t seconds)
    {
        std::unique_lock<std::mutex> lm(m_lock);
        if (m_saved_exception)
            std::rethrow_exception(m_saved_exception);

        if (!m_pop_cv.wait_for(lm, std::chrono::seconds(seconds), [this]() noexcept { return m_pop_flag; }))
            return false;

        PPORT_MESSAGE msg = (PPORT_MESSAGE)m_buffer.data();
        if (msg->u1.s1.TotalLength > size)
            throw container_overflow_exception(__FUNCTION_NAME__);

        memcpy(buffer, m_buffer.data(), msg->u1.s1.TotalLength);
        m_pop_flag = false;
        m_push_flag = true;
        m_push_cv.notify_one();

        return true;
    }

    inline void blocking_slot::push_with_exception_saving(PPORT_MESSAGE msg)
    {
        std::unique_lock<std::mutex> lm(m_lock);
        try
        {
            push(msg, lm);
        }
        catch (std::exception& ex)
        {
            m_saved_exception = std::current_exception();
        }
    }

    template<class Predicate>
    inline alpc_connection* alpc_server_engine::accept(const Predicate& predicate, uint16_t timeout_sec)
    {
        do
        {
            if (m_accept_slot.pop(m_buffer.data(), m_buffer.size(), timeout_sec))
                break;

            if (!predicate())
                fail_status<user_stop_request_exception>(m_ok, __FUNCTION_NAME__);
        } while (true);
        
        auto new_connection = std::make_unique<alpc_connection>(nullptr);
        HANDLE new_connection_handle = nullptr;
        auto status = ntdll.NtAlpcAcceptConnectPort(&new_connection_handle, m_alpc_port, 0, nullptr, nullptr, new_connection.get(), (PPORT_MESSAGE)m_buffer.data(), nullptr, TRUE);
        if (!NT_SUCCESS(status))
            throw socket_accept_exception(ntdll.RtlNtStatusToDosError(status), __FUNCTION_NAME__);

        new_connection->m_connection_handle = new_connection_handle;
        return new_connection.release();  
    }

    template<class Predicate>
    inline size_t alpc_server_data_engine::read(char* message, size_t size, const Predicate& predicate, uint16_t timeout_sec)
    {
        PPORT_MESSAGE msg = (PPORT_MESSAGE)m_buffer.data();
        if (size < msg->u1.s1.DataLength)
            throw container_overflow_exception(__FUNCTION_NAME__);

        do
        {
            if (m_connection->m_slot.pop(m_buffer.data(), m_buffer.size(), timeout_sec))
                break;

            if (!predicate())
                fail_status<user_stop_request_exception>(m_ok, __FUNCTION_NAME__);
        } while (true);

        if ((msg->u2.s2.Type & LPC_MESSAGE_TYPE) != LPC_REQUEST)
            fail_status<socket_read_exception>(m_ok, 0, __FUNCTION_NAME__);

        m_id = msg->MessageId;
        memcpy(message, msg + 1, msg->u1.s1.DataLength);

        return msg->u1.s1.DataLength;
    }

    template<class Predicate>
    inline void alpc_server_data_engine::write(const char* message, const Predicate& predicate, uint16_t /*timeout_sec*/)
    {
        PPORT_MESSAGE msg = (PPORT_MESSAGE)m_buffer.data();
        memset(msg, 0, sizeof(PORT_MESSAGE));
        size_t size = *(__MSG_LENGTH_TYPE__*)message + sizeof(PORT_MESSAGE);
        if (size > m_buffer.size())
            throw container_overflow_exception(__FUNCTION_NAME__);

        msg->u1.s1.TotalLength = size;
        msg->u1.s1.DataLength = msg->u1.s1.TotalLength - sizeof(PORT_MESSAGE);
        msg->MessageId = m_id;
        memcpy(msg + 1, message, msg->u1.s1.DataLength);

        auto status = ntdll.NtAlpcSendWaitReceivePort(m_alpc_port, ALPC_MSGFLG_RELEASE_MESSAGE, msg, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!NT_SUCCESS(status))
            fail_status<socket_write_exception>(m_ok, ntdll.RtlNtStatusToDosError(status), __FUNCTION_NAME__);
    }

    DWORD CALLBACK io_job(void* context);
    struct io_ctx
    {
        std::promise<NTSTATUS> promise;
        HANDLE alpc_port;
        PPORT_MESSAGE msg;
        SIZE_T resp_max_len;

        io_ctx(HANDLE _alpc_port, PPORT_MESSAGE _msg, SIZE_T _resp_max_len) : alpc_port(_alpc_port), msg(_msg), resp_max_len(_resp_max_len) {}
    };

    DWORD CALLBACK io_job(void* context);

    template<class Predicate>
    inline void alpc_client_engine::send_request(const char* request, char* response, size_t response_size, const Predicate& predicate, uint16_t timeout_sec)
    {
        size_t request_size = *(__MSG_LENGTH_TYPE__*)request + sizeof(PORT_MESSAGE);
        if (request_size > m_buffer.size())
            throw container_overflow_exception(__FUNCTION_NAME__);

        PPORT_MESSAGE msg = (PPORT_MESSAGE)m_buffer.data();
        memset(msg, 0, sizeof(PORT_MESSAGE));
        msg->u1.s1.TotalLength = request_size;
        msg->u1.s1.DataLength = msg->u1.s1.TotalLength - sizeof(PORT_MESSAGE);
        memcpy(msg + 1, request, msg->u1.s1.DataLength);

        SIZE_T len = response_size + sizeof(PORT_MESSAGE);
        if (len > m_buffer.size())
            throw container_overflow_exception(__FUNCTION_NAME__);

        io_ctx ctx(m_alpc_port, msg, len);
        auto future = ctx.promise.get_future();

        auto res = QueueUserWorkItem(io_job, &ctx, WT_EXECUTELONGFUNCTION);

        NTSTATUS status = 0;
        bool closed_by_user = false;
        while (std::future_status::timeout == future.wait_for(std::chrono::seconds(timeout_sec)))
        {
            if (!predicate())
            {
                closed_by_user = true;
                close();
            }
        }

        status = future.get();
        if (!NT_SUCCESS(status))
        {
            if (closed_by_user)
                fail_status<user_stop_request_exception>(m_ok, __FUNCTION_NAME__);

            fail_status<socket_read_exception>(m_ok, ntdll.RtlNtStatusToDosError(status), __FUNCTION_NAME__);
        }

        memcpy(response, msg + 1, msg->u1.s1.DataLength);
    }

#endif // _WIN32 || USE_ALPC
}

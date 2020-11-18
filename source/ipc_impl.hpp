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
    static bool wait_for(socket_t s, const Predicate& predicate)
    {
        timeval timeout = { 1, 0 };
        int count = 0;
        while (count == 0)
        {
            if (!predicate())
                throw user_stop_request_exception(__FUNCTION_NAME__);

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            if constexpr (Reading)
                count = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
            else
                count = select(FD_SETSIZE, nullptr, &fds, nullptr, &timeout);
        };
    
        return (count >= 0);
    }
    
    template<typename Predicate>
    inline void point_to_point_socket::wait_for_shutdown(const Predicate& predicate)
    {
        wait_for<true>(m_socket, predicate);
    }
    
    #ifdef _WIN32
    static inline int get_socket_error() noexcept { return WSAGetLastError(); }
    #else
    static inline int get_socket_error() noexcept { return errno; }
    #endif
    
    template<typename Predicate>
    inline point_to_point_socket server_socket::accept(const Predicate& predicate)
    {
        do
        {
            std::lock_guard<std::mutex> lm(m_lock);
            if (!wait_for<true>(m_socket, predicate))
                throw socket_accept_exception(get_socket_error(), __FUNCTION_NAME__);
    
    #ifdef __LINUX__
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
                return point_to_point_socket(p2p_socket);
        } while (true);
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

    template <typename exception_t, typename... Args>
    [[noreturn]] static inline bool fail_status(bool& status, Args&&... args)
    {
        status = false;
        throw exception_t(std::forward<Args>(args)...);
    }

    template<typename Predicate>
    inline bool point_to_point_socket::read_message(std::vector<char>& message, const Predicate& predicate)
    {
        check_status<bad_socket_exception>(m_ok, __FUNCTION_NAME__);

        size_t read = 0;
        size_t size = (size_t)(-1);
        while (read < std::min<size_t>(message.size(), size))
        {
            if (!wait_for<true>(m_socket, predicate))
                fail_status<socket_read_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);
    
            int result = recv(m_socket, message.data() + read, message.size() - read, 0);
            if (result < 0)
            {
#ifdef __unix__
                if (get_socket_error() == EAGAIN)
                    continue;
#endif

                break;
            }
            else if (result != 0)
            {
                read += (uint32_t)result;
                if (read >= sizeof(__MSG_LENGTH_TYPE__))
                    size = *(__MSG_LENGTH_TYPE__*)message.data();
            }
            else
                break;
        }
    
        return update_status<socket_read_exception>(m_ok, read == size, get_socket_error(), __FUNCTION_NAME__);
    }
    
    template<typename Predicate>
    inline bool point_to_point_socket::write_message(const char* message, const Predicate& predicate)
    {
        check_status<bad_socket_exception>(m_ok, __FUNCTION_NAME__);

        do
        {
            if (!wait_for<false>(m_socket, predicate))
                return fail_status<socket_write_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);

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
    
                return fail_status<socket_write_exception>(m_ok, get_socket_error(), __FUNCTION_NAME__);
            }
        } while (true);
    }
    
    inline void point_to_point_socket::shutdown() noexcept
    {
        ::shutdown(m_socket, SD_SEND);
        m_ok = false;
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

    template<typename callable_t, typename... Args>
    [[noreturn]] static void fail_status(callable_t& c, bool& status, Args&&... args)
    {
        status = false;
        c(std::forward<Args>(args)...);
    }

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
    
    template<typename pred>
    inline bool point_to_point_socket::read_message(in_message& message, const pred& predicate)
    {
        message.clear();
        try
        {
            return read_message(message.get_data(), predicate);
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
}

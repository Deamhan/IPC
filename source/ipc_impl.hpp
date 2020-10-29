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
    template<typename pred, bool reading>
    static bool wait_for(socket_t s, const pred& predicate)
    {
        timeval timeout = { 1, 0 };
        int count = 0;
        bool need_stop = false;
        while (count == 0)
        {
            need_stop = !predicate();
            if (need_stop)
                break;
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            if constexpr (reading)
                count = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
            else
                count = select(FD_SETSIZE, nullptr, &fds, nullptr, &timeout);
        };
    
        return !(count < 0 || need_stop);
    }
    
    template<bool use_exceptions> template<typename pred>
    inline void point_to_point_socket<use_exceptions>::wait_for_shutdown(const pred& predicate)
    {
        wait_for<pred, true>(m_socket, predicate);
    }
    
    #ifdef _WIN32
    static inline int get_socket_error() noexcept { return WSAGetLastError(); }
    #else
    static inline int get_socket_error() noexcept { return errno; }
    #endif
    
    template <bool use_exceptions> template<typename pred>
    inline point_to_point_socket<use_exceptions> server_socket<use_exceptions>::accept(const pred& predicate)
    {
        socket_t p2p_socket = INVALID_SOCKET;
        do
        {
            std::lock_guard<std::mutex> lm(m_lock);
            if (!wait_for<pred, true>(m_socket, predicate))
                break;
    
    #ifdef __LINUX__
            p2p_socket = ::accept4(m_socket, nullptr, 0, SOCK_NONBLOCK);
    #else
            p2p_socket = ::accept(m_socket, nullptr, 0);
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
                {
                    if constexpr (use_exceptions)
                        throw socket_accept_exception(__FUNCTION_NAME__);
                    else
                        break;
                }
            }
            else
                break;
        } while (true);
    
        return point_to_point_socket<use_exceptions>(p2p_socket);
    }
    
    template <bool use_exceptions, typename exception_t, typename text_t>
    static bool check_status(text_t&& text, bool status) noexcept(!use_exceptions)
    {
        if (!status)
        {
            if constexpr (use_exceptions)
                throw exception_t(std::forward<text_t>(text));
            else
                return false;
        }

        return true;
    }

    template <bool use_exceptions, typename exception_t, typename string_t>
    static inline bool update_status(string_t&& text, bool& status, bool new_status) noexcept(use_exceptions)
    {
        status = new_status;
        return check_status<use_exceptions, exception_t>(forward<string_t>(text), status);
    }

    template<bool use_exceptions> template<typename pred>
    inline bool point_to_point_socket<use_exceptions>::read_message(std::vector<char>& message, const pred& predicate)
    {
        if (!check_status<use_exceptions, bad_channel_exception>(__FUNCTION_NAME__, m_ok))
            return false;

        size_t read = 0;
        size_t size = (size_t)(-1);
        while (read < std::min<size_t>(message.size(), size))
        {
            if (!wait_for<pred, true>(m_socket, predicate))
                return update_status<use_exceptions, channel_read_exception>(__FUNCTION_NAME__, m_ok, false);
    
            int result = recv(m_socket, message.data() + read, message.size() - read, 0);
            if (result < 0)
            {
    #ifdef __unix__
                if (get_socket_error() == EAGAIN)
                    continue;
    #endif

                return update_status<use_exceptions, channel_read_exception>(__FUNCTION_NAME__, m_ok, read == size);
            }
            else if (result != 0)
            {
                read += (uint32_t)result;
                if (read >= sizeof(__MSG_LENGTH_TYPE__))
                    size = *(__MSG_LENGTH_TYPE__*)message.data();
            }
            else
                return update_status<use_exceptions, channel_read_exception>(__FUNCTION_NAME__, m_ok, read == size);
        }
    
        return update_status<use_exceptions, channel_read_exception>(__FUNCTION_NAME__, m_ok, read == size);
    }
    
    template <bool use_exception> template<typename pred>
    inline bool point_to_point_socket<use_exception>::write_message(const char* message, const pred& predicate)
    {
        if (!check_status<use_exceptions, bad_channel_exception>(__FUNCTION_NAME__, m_ok))
            return false;

        do
        {
            if (!wait_for<pred, false>(m_socket, predicate))
                return update_status<use_exceptions, channel_write_exception>(__FUNCTION_NAME__, m_ok, false);

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
    
                return update_status<use_exceptions, channel_write_exception>(__FUNCTION_NAME__, m_ok, false);
            }
        } while (true);
    }
    
    template <bool use_exceptions>
    inline void unix_client_socket<use_exceptions>::shutdown()
    {
        ::shutdown(m_socket, SD_SEND);
        m_ok = false;
    }

    template <>
    struct message::tag_traits<uint32_t>
    {
        static const message::tag_t value = message::tag_t::u32;
    };
    
    template <>
    struct message::tag_traits<int32_t>
    {
        static const message::tag_t value = message::tag_t::i32;
    };
    
    template <>
    struct message::tag_traits<int64_t>
    {
        static const message::tag_t value = message::tag_t::i64;
    };
    
    template <>
    struct message::tag_traits<uint64_t>
    {
        static const message::tag_t value = message::tag_t::u64;
    };
    
    template <>
    struct message::tag_traits<double>
    {
        static const message::tag_t value = message::tag_t::fp64;
    };
    
    
    template <>
    struct message::tag_traits<const char*>
    {
        static const message::tag_t value = message::tag_t::str;
    };
    
    template <>
    struct message::tag_traits<std::string>
    {
        static const message::tag_t value = message::tag_t::str;
    };
    
    template <>
    struct message::tag_traits<char>
    {
        static const message::tag_t value = message::tag_t::chr;
    };
    
    template <>
    struct message::tag_traits<message::remote_ptr>
    {
        static const message::tag_t value = message::tag_t::remote_ptr;
    };
    
    template <>
    struct message::trivial_type<int32_t>
    {
        static const bool value = true;
    };

    template <>
    struct message::trivial_type<uint32_t>
    {
        static const bool value = true;
    };

    template <>
    struct message::trivial_type<int64_t>
    {
        static const bool value = true;
    };

    template <>
    struct message::trivial_type<uint64_t>
    {
        static const bool value = true;
    };

    template <>
    struct message::trivial_type<double>
    {
        static const bool value = true;
    };

    template <>
    struct message::trivial_type<char>
    {
        static const bool value = true;
    };

    [[noreturn]] void throw_message_overflow_exception(const char* func_name, size_t req_size, size_t total_size);
    [[noreturn]] void throw_type_mismatch_exception(const char* func_name, const char* tag, const char* expected);
    [[noreturn]] void throw_message_too_short_exception(const char* func_name, size_t req_size, size_t total_size);
    [[noreturn]] void throw_container_overflow_exception(const char* func_name, size_t req_size, size_t total_size);

    template<bool use_exceptions, typename callable_t, typename... Args>
    static void fail_status_without_result(callable_t& c, bool& status, Args&&... args) noexcept(!use_exceptions)
    {
        status = false;
        if constexpr (use_exceptions)
            c(std::forward<Args>(args)...);
    }

    template<bool use_exceptions, typename callable_t, typename return_value_t, typename... Args>
    static return_value_t& fail_status(callable_t& c, bool& status, return_value_t& result, Args&&... args) noexcept(!use_exceptions)
    {
        fail_status_without_result<use_exceptions>(c, status, std::forward<Args>(args)...);

        return result;
    }

    template <bool use_exceptions> template <typename T, message::tag_t tag, typename>
    inline out_message<use_exceptions>& out_message<use_exceptions>::push(T arg)
    {
        if (!check_status<use_exceptions, bad_message_exception>(std::string(__FUNCTION_NAME__) + ": fail flag is set", m_ok))
            return *this;

    #if __MSG_USE_TAGS__
        const size_t delta = 1;
    #else
        const size_t delta = 0;
    #endif // __MSG_USE_TAGS__
        size_t used = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
        size_t new_used = used + sizeof(T) + delta;
        if (new_used > get_max_size())
            return fail_status<use_exceptions>(throw_message_overflow_exception, m_ok, *this, __FUNCTION_NAME__, new_used, get_max_size());
    
    #if __MSG_USE_TAGS__
        m_buffer.push_back((char)tag);
    #endif // __MSG_USE_TAGS__
        const char* data = (const char*)&arg;
        m_buffer.insert(m_buffer.end(), data, data + sizeof(T));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = (__MSG_LENGTH_TYPE__)new_used;
    
        return *this;
    }
    
    template <bool use_exceptions>
    inline void out_message<use_exceptions>::clear()
    {
        m_buffer.resize(sizeof(__MSG_LENGTH_TYPE__));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
    }
    
    template <bool use_exceptions>
    inline void in_message<use_exceptions>::clear()
    {
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
        m_offset = sizeof(__MSG_LENGTH_TYPE__);
    }
    
    template <bool use_exceptions> template <typename T, message::tag_t expected_tag, typename>
    inline in_message<use_exceptions>& in_message<use_exceptions>::pop(T& arg)
    {
        if (!check_status<use_exceptions, bad_message_exception>(std::string(__FUNCTION_NAME__) + ": fail flag is set", m_ok))
            return *this;

#if __MSG_USE_TAGS__
        const size_t delta = 1;
#else
        const size_t delta = 0;
#endif // __MSG_USE_TAGS__

        const size_t size = *(const __MSG_LENGTH_TYPE__*)m_buffer.data();
        size_t new_offset = m_offset + sizeof(T) + delta;
        if (size < new_offset)
            return fail_status<use_exceptions>(throw_message_too_short_exception, m_ok, *this, __FUNCTION_NAME__, new_offset, size);
        else
        {
#if __MSG_USE_TAGS__
            message::tag_t tag = (message::tag_t)m_buffer[m_offset];
            if (expected_tag != tag)
                return fail_status<use_exceptions>(throw_type_mismatch_exception, m_ok, *this, __FUNCTION_NAME__, tag, expected_tag);

            ++m_offset;
#endif // __MSG_USE_TAGS__
            arg = *(T*)&m_buffer[m_offset];
            m_offset = new_offset;
        }
    
        return *this;
    }
    
    template <bool use_exceptions> template<typename pred>
    inline bool point_to_point_socket<use_exceptions>::read_message(in_message<use_exceptions>& message, const pred& predicate)
    {
        message.clear();
        if constexpr (use_exceptions)
        {
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
        else
        {
            bool result = read_message(message.get_data(), predicate);
            if (!result)
                message.clear();

            return result;
        }
    }
    
    template <bool use_exceptions> template <size_t N>
    inline in_message<use_exceptions>& in_message<use_exceptions>::operator >> (std::pair<std::array<uint8_t, N>, size_t>& blob)
    {
        if (!check_status<use_exceptions, bad_message_exception>(std::string(__FUNCTION_NAME__) + ": fail flag is set", m_ok))
            return *this;

        __MSG_LENGTH_TYPE__ size = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
#if __MSG_USE_TAGS__
        const size_t delta = 1 + sizeof(__MSG_LENGTH_TYPE__);
#else
        const size_t delta = sizeof(__MSG_LENGTH_TYPE__);
#endif // __MSG_USE_TAGS__
        if (size < m_offset + delta)
            return fail_status<use_exceptions>(throw_message_too_short_exception, m_ok, *this, __FUNCTION_NAME__, m_offset + delta, size);

#if __MSG_USE_TAGS__
        tag_t tag = (tag_t)m_buffer[m_offset];
        if (tag != tag_t::blob)
            return fail_status<use_exceptions>(throw_type_mismatch_exception, m_ok, *this, __FUNCTION_NAME__, tag, tag_t::blob);

        ++m_offset;
#endif // __MSG_USE_TAGS__

        const __MSG_LENGTH_TYPE__ blob_len = *(const __MSG_LENGTH_TYPE__*)&m_buffer[m_offset];
        m_offset += sizeof(__MSG_LENGTH_TYPE__);

        if (size < m_offset + blob_len)
            return fail_status<use_exceptions>(throw_message_too_short_exception, m_ok, *this, __FUNCTION_NAME__, m_offset + blob_len, size);

        if (blob_len > N)
            return fail_status<use_exceptions>(throw_container_overflow_exception, m_ok, *this, __FUNCTION_NAME__, blob_len, N);

        if (blob_len != 0)
        {
            memcpy(blob.first.data(), &m_buffer[m_offset], blob_len);
            m_offset += blob_len;
        }

        blob.second = blob_len;
    
        return *this;
    }
}

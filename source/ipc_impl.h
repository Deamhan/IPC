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

#include "../include/ipc.h"

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
    
    template<typename pred>
    inline void point_to_point_socket::wait_for_shutdown(const pred& predicate)
    {
        wait_for<pred, true>(m_socket, predicate);
    }
    
    #ifdef _WIN32
    static inline int get_socket_error() noexcept { return WSAGetLastError(); }
    #else
    static inline int get_socket_error() noexcept { return errno; }
    #endif
    
    template<typename pred>
    inline point_to_point_socket server_socket::accept(const pred& predicate)
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
                    break;
            }
            else
                break;
        } while (true);
    
        return point_to_point_socket(p2p_socket);
    }
    
    template<typename pred>
    inline bool point_to_point_socket::read_message(std::vector<char>& message, const pred& predicate)
    {
        size_t read = 0;
        size_t size = (size_t)(-1);
        while (read < std::min<size_t>(message.size(), size))
        {
            if (!wait_for<pred, true>(m_socket, predicate))
                return false;
    
            int result = recv(m_socket, message.data() + read, message.size() - read, 0);
            if (result < 0)
            {
    #ifdef __unix__
                if (get_socket_error() == EAGAIN)
                    continue;
    #endif
    
                return (read == size);
            }
            else if (result != 0)
            {
                read += (uint32_t)result;
                if (read >= sizeof(__MSG_LENGTH_TYPE__))
                    size = *(__MSG_LENGTH_TYPE__*)message.data();
            }
            else
                return (read == size); // is it correct?
        }
    
        return (read == size);
    }
    
    template<typename pred>
    inline bool point_to_point_socket::write_message(const char* message, const pred& predicate)
    {
        do
        {
            if (!wait_for<pred, false>(m_socket, predicate))
                return false;
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
    
                return false;
            }
        } while (true);
    }
    
    inline void unix_client_socket::shutdown()
    {
        ::shutdown(m_socket, SD_SEND);
    }

    template <>
    struct message::TagTraits<uint32_t>
    {
        static const message::Tag value = message::Tag::u32;
    };
    
    template <>
    struct message::TagTraits<int32_t>
    {
        static const message::Tag value = message::Tag::i32;
    };
    
    template <>
    struct message::TagTraits<int64_t>
    {
        static const message::Tag value = message::Tag::i64;
    };
    
    template <>
    struct message::TagTraits<uint64_t>
    {
        static const message::Tag value = message::Tag::u64;
    };
    
    template <>
    struct message::TagTraits<double>
    {
        static const message::Tag value = message::Tag::fp64;
    };
    
    
    template <>
    struct message::TagTraits<const char*>
    {
        static const message::Tag value = message::Tag::str;
    };
    
    template <>
    struct message::TagTraits<std::string>
    {
        static const message::Tag value = message::Tag::str;
    };
    
    template <>
    struct message::TagTraits<char>
    {
        static const message::Tag value = message::Tag::chr;
    };
    
    template <>
    struct message::TagTraits<message::remote_ptr>
    {
        static const message::Tag value = message::Tag::remote_ptr;
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

    template <typename T, message::Tag TAG, typename>
    inline out_message& out_message::push(T arg)
    {
    #if __MSG_USE_TAGS__
        const size_t delta = 1;
    #else
        const size_t delta = 0;
    #endif // __MSG_USE_TAGS__
        size_t used = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
        size_t new_used = used + sizeof(T) + delta;
        if (new_used > get_max_size())
        {
            m_ok = false;
            return *this;
        }
    
    #if __MSG_USE_TAGS__
        m_buffer.push_back((char)TAG);
    #endif // __MSG_USE_TAGS__
        const char* data = (const char*)&arg;
        m_buffer.insert(m_buffer.end(), data, data + sizeof(T));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = (__MSG_LENGTH_TYPE__)new_used;
    
        return *this;
    }
    
    template <typename T, typename>
    inline out_message& out_message::operator << (T arg)
    {
        return push<T, TagTraits<T>::value>(arg);
    }
    
    inline void out_message::clear()
    {
        m_buffer.resize(sizeof(__MSG_LENGTH_TYPE__));
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
    }
    
    inline void in_message::clear()
    {
        *(__MSG_LENGTH_TYPE__*)m_buffer.data() = sizeof(__MSG_LENGTH_TYPE__);
        m_ok = true;
        m_offset = sizeof(__MSG_LENGTH_TYPE__);
    }
    
    template <typename T, message::Tag TAG, typename>
    inline in_message& in_message::pop(T& arg)
    {
        if (m_ok)
        {
    #if __MSG_USE_TAGS__
            const size_t delta = 1;
    #else
            const size_t delta = 0;
    #endif // __MSG_USE_TAGS__
    
            const size_t size = *(const __MSG_LENGTH_TYPE__*)m_buffer.data();
            size_t new_offset = m_offset + sizeof(T) + delta;
            if (size < new_offset)
                m_ok = false;
            else
            {
    #if __MSG_USE_TAGS__
                message::Tag tag = (message::Tag)m_buffer[m_offset];
                if (tag != TAG)
                {
                    m_ok = false;
                    return *this;
                }
                ++m_offset;
    #endif // __MSG_USE_TAGS__
                arg = *(T*)&m_buffer[m_offset];
                m_offset = new_offset;
            }
        }
    
        return *this;
    }
    
    template <typename T, typename>
    inline in_message& in_message::operator >> (T& arg)
    {
        return pop<T, TagTraits<T>::value>(arg);
    }
    
    template<typename pred>
    inline bool point_to_point_socket::read_message(in_message& message, const pred& predicate)
    {
        message.clear();
        return read_message(message.get_data(), predicate);
    }
    
    inline void socket::close() noexcept
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
    
    template <size_t N>
    inline in_message& in_message::operator >> (std::pair<std::array<uint8_t, N>, size_t>& blob)
    {
        if (m_ok)
        {
            __MSG_LENGTH_TYPE__ size = *(__MSG_LENGTH_TYPE__*)m_buffer.data();
    #if __MSG_USE_TAGS__
            const size_t delta = 1 + sizeof(__MSG_LENGTH_TYPE__);
    #else
            const size_t delta = sizeof(__MSG_LENGTH_TYPE__);
    #endif // __MSG_USE_TAGS__
            if (size < m_offset + delta)
            {
                m_ok = false;
                return *this;
            }
    
    #if __MSG_USE_TAGS__
            Tag tag = (Tag)m_buffer[m_offset];
            if (tag != Tag::blob)
            {
                m_ok = false;
                return *this;
            }
            ++m_offset;
    #endif // __MSG_USE_TAGS__
    
            const __MSG_LENGTH_TYPE__ blob_len = *(const __MSG_LENGTH_TYPE__*)&m_buffer[m_offset];
            m_offset += sizeof(__MSG_LENGTH_TYPE__);
    
            if (size < m_offset + blob_len || blob_len > N)
            {
                m_ok = false;
                return *this;
            }
    
            if (blob_len != 0)
            {
                memcpy(blob.first.data(), &m_buffer[m_offset], blob_len);
                m_offset += blob_len;
            }
    
            blob.second = blob_len;
        }
    
        return *this;
    }
}

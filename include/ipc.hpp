/**
 * Lightweight inter process communication library
 * Copyright (C) 2020 Pavel Kovalenko 
 *
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <array>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _WIN32
#   define FD_SETSIZE 1024
#   include <winsock2.h>
#   include <windows.h>
#   ifdef __AFUNIX_H__
#       include <afunix.h>
#   endif // __AFUNIX_H__
#   define PATH_SEP '\\'
    typedef SOCKET socket_t;
#else
#   include <fcntl.h>
#   include <netinet/in.h>
#   include <unistd.h>
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <sys/un.h>
#   define PATH_SEP '/'
#   define stricmp strcasecmp
    typedef int socket_t;
#   ifndef INVALID_SOCKET
#       define INVALID_SOCKET (-1)
#   endif // INVALID_SOCKET
#   define SD_SEND SHUT_WR
#endif // _WIN32

/**
* \brief Tag usage control macro.
* 
* To disable type control and increase performance (and reduce message overhead) set __MSG_USE_TAGS__ to 0.
*/
#ifndef __MSG_USE_TAGS__
#define __MSG_USE_TAGS__ 1
#endif // __MSG_USE_TAGS__

/**
* \brief Message length type control macro.
* 
* Type must be long enough to hold length of application messages (type must be unsigned). But too long types will increase message overhead. 
* __MSG_LENGTH_TYPE__ is uint16_t by default.
*/
#ifndef __MSG_LENGTH_TYPE__
#   define __MSG_LENGTH_TYPE__ uint16_t
#else
    static_assert(std::is_unsigned_v(__MSG_LENGTH_TYPE__) && sizeof(__MSG_LENGTH_TYPE__) <= sizeof(size_t), "__MSG_LENGTH_TYPE__ must be unsigned integral type less or equal size_t");
#endif // __MSG_LENGTH_TYPE__

#ifdef max
#undef max
#endif // max

/**
* \brief Max message length control macro.
* 
* Should be long enough to hold application messages, but be caution: too high value may cause memory exhaustion.
* __MSG_MAX_LENGTH__ is std::numeric_limits<__MSG_LENGTH_TYPE__>::max() by default.
*/
#ifndef __MSG_MAX_LENGTH__
    static const size_t msg_max_length = std::numeric_limits<__MSG_LENGTH_TYPE__>::max();
#else
    static_assert(__MSG_MAX_LENGTH__ <= std::numeric_limits<__MSG_LENGTH_TYPE__>::max(), "__MSG_LENGTH_TYPE__ is too short for __MSG_MAX_LENGTH__");
    static const size_t msg_max_length = __MSG_MAX_LENGTH__;
#endif // __MSG_MAX_LENGTH__


namespace ipc
{
    class channel_exception : public std::runtime_error
    {
    protected:
        template <class T>
        explicit channel_exception(T&& message) : std::runtime_error(std::forward<T>(message)) {}
    };

    class socket_api_failed_exception : public std::runtime_error
    {
    public:
        template <class T>
        explicit socket_api_failed_exception(T&& message) : std::runtime_error(std::forward<T>(message)) {}
    };

    class bad_channel_exception : public std::logic_error
    {
    public:
        template <class T>
        explicit bad_channel_exception(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    class container_overflow_exception : public std::logic_error
    {
    public:
        template <class T>
        explicit container_overflow_exception(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    class message_format_exception : public std::logic_error
    {
    protected:
        template <class T>
        explicit message_format_exception(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    class type_mismach_exception : public message_format_exception
    {
    public:
        template <class T>
        explicit type_mismach_exception(T&& message) : message_format_exception(std::forward<T>(message)) {}
    };

    class message_too_short_exception : public message_format_exception
    {
    public:
        template <class T>
        explicit message_too_short_exception(T&& message) : message_format_exception(std::forward<T>(message)) {}
    };

    class bad_message_exception : public std::logic_error
    {
    public:
        template <class T>
        explicit bad_message_exception(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    class message_overflow_exception : public std::logic_error
    {
    public:
        template <class T>
        explicit message_overflow_exception(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    class channel_read_exception : public channel_exception
    {
    public:
        template <class T>
        explicit channel_read_exception(T&& message) : channel_exception(std::forward<T>(message)) {}
    };

    class channel_write_exception : public channel_exception
    {
    public:
        template <class T>
        explicit channel_write_exception(T&& message) : channel_exception(std::forward<T>(message)) {}
    };

    class passive_socket_exception : public channel_exception
    {
    protected:
        template <class T>
        explicit passive_socket_exception(T&& message) : channel_exception(std::forward<T>(message)) {}
    };

    class socket_prepare_exception : public passive_socket_exception
    {
    public:
        template <class T>
        explicit socket_prepare_exception(T&& message) : passive_socket_exception(std::forward<T>(message)) {}
    };

    class socket_accept_exception : public passive_socket_exception
    {
    public:
        template <class T>
        explicit socket_accept_exception(T&& message) : passive_socket_exception(std::forward<T>(message)) {}
    };

    class unknown_message_tag : public std::logic_error
    {
    public:
        template <class T>
        explicit unknown_message_tag(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Base class for all sockets hierarchy.
     */
    template <bool use_exceptions>
    class socket
    {
    public:
        bool is_ok() const noexcept { return m_ok; } ///< checks socket state
        operator bool() const noexcept { return is_ok(); } ///< checks socket state

        socket(const socket&) = delete;
        socket& operator = (const socket&) = delete;
        void close() noexcept; ///< closes socket
    protected:
        bool m_ok;
        socket_t m_socket;
        explicit socket(socket_t socket) noexcept(!use_exceptions);
    };

    /**
     * \brief Base class for all messages hierarchy.
     *
     * Message is memory buffer with some kind of serialized data. Message buffer starts with size which type is __MSG_LENGTH_TYPE__ .
     * Total message buffer length includes size header.
     */
    class message
    {
    public:
        /**
         * \brief Simple raw pointer wrapper.
         *
         * Can't be used on another side, but can be used as callback parameter as context for example.
         * This wrapper can be used even between applications of different bitness.
         */
        class remote_ptr
        {
        public:
            /**
             * \brief Extracts underlying pointer.
             *
             * \return raw pointer
             */
            void* get_pointer() const noexcept { return (void*)(uintptr_t)m_ptr; } 
            
            /**
             * \brief Creates wrapper from raw pointer.
             *
             * \param p raw pointer
             */
            explicit remote_ptr(void* p = nullptr) noexcept : m_ptr((uintptr_t)p) {} ///< 
        protected:
            uint64_t m_ptr;

            friend class message;
        };

        constexpr size_t get_max_size() const { return msg_max_length; } ///< returns max available message buffer size
        bool is_ok() const noexcept { return m_ok; } ///< checks message state
        operator bool() const noexcept { return is_ok(); } ///< checks message state

        template <class T>
        struct trivial_type;

        void reset_fail_state() noexcept { m_ok = true; }

    protected:
        /**
         * \brief One byte type tags.
         *
         * More complicated types can be built from this primitives. Unused if __MSG_USE_TAGS__ is 0.
         */
        enum class tag_t : uint8_t
        {
            u32 = 0,
            i32,
            u64,
            i64,
            fp64,
            str,
            chr,
            remote_ptr,
            blob
        };

#ifdef __AFUNIX_H__
        const char* to_string(tag_t t) noexcept;
#endif //_AFUNIX_H__

        bool m_ok;
        
        template <typename T> 
        struct tag_traits;

        template <typename T>
        friend struct tag_traits;

        message() noexcept : m_ok(true) {}
        message(const message&) = delete;
        message& operator=(const message&) = delete;

        uint64_t get_u64_ptr(const remote_ptr& p) const noexcept { return p.m_ptr; }
        uint64_t& get_u64_ptr(remote_ptr& p) noexcept { return p.m_ptr; }
    };

    /**
     * \brief Output message type.
     *
     * This class serializes user's data to its internal buffer which max size is __MSG_MAX_LENGTH__.
     * Filled message should be passed to PointToPointSocket::write_message function.
     *
     * \tparam use_exceptions throw exception on error in addition to set fail status
     */
    template <bool use_exceptions>
    class out_message : public message
    {
    public:
        /**
         * \brief Serializes user's data of arithmetic type to internal buffer.
         * \param arg - data to serialize.
         */
        template <typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        out_message& operator << (T arg) { return push<T, tag_traits<T>::value>(arg); }

        /**
         * \brief Serializes user's data of string type (std::string, const char*, std::string_view) to internal buffer.
         * \param s - string to serialize.
         */
        out_message& operator << (const std::string_view& s);
        
        /**
         * \brief Serializes user's pointer to internal buffer.
         * \param p - pointer to serialize.
         */
        out_message& operator << (const remote_ptr& p) { return push<uint64_t, Tag::remote_ptr>(get_u64_ptr(p)); }
        
        /**
         * \brief Serializes user's blob to internal buffer.
         * \param blob - blob to serialize.
         */
        out_message& operator << (const std::pair<const uint8_t*, size_t>& blob);
        
        /**
         * \brief Resets message to empty state.
         */
        void clear(); 
        
        out_message() { clear(); }
        
        /**
         * \brief Returns underlying data buffer.
         */
        const std::vector<char>& get_data() const noexcept { return m_buffer; }
        
    protected:
        template <typename T, tag_t tag, typename = std::enable_if_t<trivial_type<T>::value>>
        out_message& push(T arg);
        
        std::vector<char> m_buffer;
    };

    /**
     * \brief Input message type.
     *
     * This class deserializes user data from its internal buffer which max size is __MSG_MAX_LENGTH__.
     * Empty message should be filled by PointToPointSocket::read_message function first.
     * 
     * \tparam use_exceptions throw exception on error in addition to set fail status
     */
    template <bool use_exceptions>
    class in_message : public message
    {
    public:
        /**
         * \brief Deserializes data of arithmetic type from internal buffer.
         * \param arg - extracted data.
         */
        template <typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        in_message& operator >> (T& arg) { return pop<T, tag_traits<T>::value>(arg); }

        /**
         * \brief Deserializes string data from internal buffer.
         * \param arg - extracted data.
         */
        in_message& operator >> (std::string& arg);
        
        /**
         * \brief Deserializes remote pointer from internal buffer.
         * \param arg - extracted data.
         */
        in_message& operator >> (remote_ptr& p) { return pop<uint64_t, Tag::remote_ptr>(get_u64_ptr(p)); }
        
        /**
         * \brief Deserializes blob from internal buffer.
         * \param arg - extracted data.
         */
        in_message& operator >> (std::vector<uint8_t>& blob);

        /**
         * \brief Deserializes blob from internal buffer. This version can be more performance efficient than previous one.
         * \param arg - extracted data. Array (first member of pair) must be long enough to store blob, second member will hold real blob size.
         */
        template <size_t N>
        in_message& operator >> (std::pair<std::array<uint8_t, N>, size_t>& blob);
        
        /**
         * \brief Resets message to empty state.
         */
        void clear();
        
        in_message() : m_buffer(get_max_size()) { clear(); }
        
        /**
         * \brief Returns underlying data buffer.
         */
        std::vector<char>& get_data() noexcept { return m_buffer; }

    protected:
        template <typename T, tag_t tag, typename = std::enable_if_t<trivial_type<T>::value>>
        in_message& pop(T& arg);

        std::vector<char> m_buffer;
        size_t m_offset;
    };

    template <bool use_exceptions>
    class server_socket;

    /**
     * \brief Bidirectional data channel.
     *
     * This class allows pair of applications to send and receive data between each other. Instance cannot be created directly:
     * it can be obtained as result of ServerSocket::accept (received instance will represent server side of data channel).
     * 
     * \tparam use_exceptions throw exception on error in addition to set fail status
     */
    template <bool use_exceptions>
    class point_to_point_socket : public socket<use_exceptions>
    {
    public:
        /**
         * \brief Reads raw message from channel. Use it only if you really need raw message form.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function 
         * will immediately return false and state of message will be invalid and must be reset.
         *
         * \param raw message buffer (length and data, see ipc::Message)
         * \param predicate function of type bool() or similar callable object 
         * \return true if message has been read successfully.
         */
        template<typename pred>
        bool read_message(std::vector<char>& message, const pred& predicate);

        /**
         * \brief Reads message from channel.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function 
         * will immediately return false and state of message will be invalid and must be reset.
         *
         * \param message object
         * \param predicate function of type bool() or similar callable object 
         * \return true if message has been read successfully.
         */
        template<typename pred>
        bool read_message(in_message<use_exceptions>& message, const pred& predicate);

        /**
          * \brief Writes raw message to channel. Use it only if you really need raw message form.
          *          
          * \p predicate may be called several times to ask if the function should continue trying to write data. If \p predicate returns false function 
          * will immediately return false and data will not be written.
          * 
          * \warning because of non blocking writing data may not be written immediatelly after function exit, so it is recommended to wait for some kind 
          * of answer from another side and only after that destroy \p message.
          *
          * \param message object
          * \param predicate function of type bool() or similar callable object 
          * \return true if message writing has been started successfully
          */
        template<typename pred>
        bool write_message(const char * message, const pred& predicate);

        /**
          * \brief Writes message to channel.
          *          
          * \p predicate may be called several times to ask if the function should continue trying to write data. If \p predicate returns false function 
          * will immediately return false and data will not be written.
          * 
          * \warning because of non blocking writing data may not be written immediatelly after function exit, so it is recommended to wait for some kind 
          * of answer from another side and only after that destroy \p message.
          *
          * \param message object
          * \param predicate function of type bool() or similar callable object 
          * \return true if message writing has been started successfully
          */
        template<typename pred>
        bool write_message(out_message<use_exceptions>& message, const pred& predicate) { return write_message(message.get_data().data(), predicate); }

        /**
          * \brief Waits for shutdown signal.
          *          
          * \p predicate may be called several times to ask if the function should continue waiting for signal. If \p predicate returns false function 
          * will immediately return.
          *
          * \param predicate function of type bool() or similar callable object 
          *
          * \sa ipc::UnixClientSocket::shutdown.
          */
        template<typename pred>
        void wait_for_shutdown(const pred& predicate);

        ~point_to_point_socket() { close(); }
    protected:
        explicit point_to_point_socket(socket_t socket) : socket(socket) {}

        friend class server_socket<use_exceptions>;
    };

#ifdef __AFUNIX_H__
    /**
     * \brief Client side of bidirectional data channel based on UNIX sockets.
     *
     * \tparam use_exceptions throw exception on error in addition to set fail status
     * 
     * \warning Unix sockets available on Windows only since Windows 10 build 17063
     */
    template <bool use_exceptions>
    class unix_client_socket : public point_to_point_socket<use_exceptions>
    {
    public:
        /**
          * \brief Tries to connect to UNIX socket \p path. Call #is_ok to check result.
          *      
          * \param path UNIX socket path
          */
        explicit unix_client_socket(const char* path);

        /**
          * \brief Sends shutdown signal.
          *          
          * \sa ipc::PointToPointSocket::wait_for_shutdown.
          */
        void shutdown();
    };
#endif //__AFUNIX_H__

    /**
     * \brief Common passive (listening) socket. Helper class only.
     * 
     * \tparam use_exceptions throw exception on error in addition to set fail status
     */
    template <bool use_exceptions>
    class server_socket : public socket<use_exceptions>
    {
    public:
        /**
         * \brief Waits for incoming connections. 
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for incoming connections. If \p predicate returns false function 
         * will immediately return disconnected socket (ipc::PointToPointSocket::is_ok on which will return false). Function returns disconnected socket on errors too,
         * so that result of ipc::PointToPointSocket::is_ok must be checked before use of the result.
         *
         * \param predicate function of type bool() or similar callable object 
         * \return socket for data exchnge
         */
        template<typename pred>
        point_to_point_socket<use_exceptions> accept(const pred& predicate);
    protected:
        server_socket() noexcept : socket(INVALID_SOCKET) {}

        std::mutex m_lock;
    };

#ifdef __AFUNIX_H__
   /**
     * \brief Unix passive (listening) socket.
     *
     * \tparam use_exceptions throw exception on error in addition to set fail status
     * 
     * \warning Unix sockets available on Windows only since Windows 10 build 17063
     */
    template <bool use_exceptions>
    class unix_server_socket : public server_socket<use_exceptions>
    {
    public:
        /**
         * \brief Tries to create UNIX socket \p path. Call #is_ok to check result.
         *      
         * \param path UNIX socket path
         */
        template <typename T, typename = std::enable_if_t<std::is_same_v<std::string, std::remove_const_t<std::remove_reference_t<T>>>>>
        explicit unix_server_socket(T&& path);
        
        ~unix_server_socket();
    protected:
        std::string m_link;
    };
#endif //__AFUNIX_H__
}

#include "../source/ipc_impl.hpp"

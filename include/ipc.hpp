/**
 * \file ipc.hpp
 *
 * \brief Basic IPC library components. 
 *
 * \copyright Copyright (C) 2020 Pavel Kovalenko. All rights reserved.<br>
 * <br>
 * This Source Code Form is subject to the terms of the Mozilla<br>
 * Public License, v. 2.0. If a copy of the MPL was not distributed<br>
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#ifndef __DOXYGEN__

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

#endif // __DOXYGEN__

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

/**
 * \brief IPC library namespace.
 */
namespace ipc
{
    /**
     * \brief Helper class to distinguish from std::system_error.
     */
    class system_error : public std::system_error
    {
    protected:  
        /**
        * \brief Exception constructor
        * 
        * \param code exception code (errno or last error on Windows)
        * \param message exception message
        */
        template <class T>
        system_error(int code, T&& message) : std::system_error(code, std::system_category(), std::forward<T>(message)) {}
    };
    
    /**
     * \brief Helper class to distinguish from std::logic_error.
     */
    class logic_error : public std::logic_error
    {
    protected:  
        /**
        * \brief Exception constructor
        * 
        * \param message exception message
        */
        template <class T>
        explicit logic_error(T&& message) : std::logic_error(std::forward<T>(message)) {}
    };
    
    /**
     * \brief Generic socket (passive or active) exception class.
     */
    class socket_exception : public system_error
    {
    protected:  
        /**
        * \brief Exception constructor
        * 
        * \param code exception code (errno or last error on Windows)
        * \param message exception message
        */
        template <class T>
        socket_exception(int code, T&& message) : system_error(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Generic passive socket exception class.
     */
    class passive_socket_exception : public socket_exception
    {
    protected:
        /**
        * \brief Exception constructor
        *
        * \param code exception code (errno or last error on Windows)
        * \param message exception message
        */
        template <class T>
        passive_socket_exception(int code, T&& message) : socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Generic active socket exception class.
     */
    class active_socket_exception : public socket_exception
    {
    protected:
        /**
        * \brief Exception constructor
        *
        * \param code exception code (errno or last error on Windows)
        * \param message exception message
        */
        template <class T>
        active_socket_exception(int code, T&& message) : socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Socket api initialization error (Windows only).
     */
    class socket_api_failed_exception : public system_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        socket_api_failed_exception(int code, T&& message) : system_error(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that was caused by use of failed socket.
     * 
     * After any kind of exception socket internal state becomes "failed" and it should not be used any more. Otherwise bad_socket_exception will be thrown.
     */
    class bad_socket_exception : public logic_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit bad_socket_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that identifies user stop request.
     * 
     * Many socket classes methods require user predicate to allow user to stop result waiting loop. If such predicate returns false ipc::user_stop_request_exception will be thrown.
     */
    class user_stop_request_exception : public logic_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit user_stop_request_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that will be thrown if container is not large enough to hold the serialized data object.
     * 
     * Some library classes methods accept fixed size containers (such as std::array) which capacity may be not enough to hold entire serialized object. Be caution with such methods.
     */
    class container_overflow_exception : public logic_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit container_overflow_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Generic message object format mismatch exception.
     */
    class message_format_exception : public std::logic_error
    {
    protected:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit message_format_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that will be thrown if serialized object can't be deserialized to user provided variable.
     *
     * If __MSG_USE_TAGS__ is enabled message classes provide basic type safety check. If user tries to deserialize object to variable of wrong type such exception will be thrown.
     */
    class type_mismach_exception : public message_format_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit type_mismach_exception(T&& message) : message_format_exception(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that will be thrown if message was truncated and object cannot be fully deserialized.
     */
    class message_too_short_exception : public message_format_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit message_too_short_exception(T&& message) : message_format_exception(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that was caused by use of failed message.
     *
     * After any kind of exception message internal state becomes "failed" and it should be cleared by ipc::message::reset_fail_state or by full message reset. Otherwise bad_message_exception will be thrown.
     */
    class bad_message_exception : public logic_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit bad_message_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief  Exception that will be thrown if hostname translation result is not IP address.
     */
    class bad_hostname_exception : public logic_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit bad_hostname_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that will be thrown if message cannot hold all user data according max size limitation.
     *
     * To avoid exception condition you should either increase __MSG_MAX_LENGTH__ or reduce data amount per message. 
     */
    class message_overflow_exception : public logic_error
    {
    public:
        /**
         * \brief exception constructor
         *
         * \param message exception message
         */
        template <class T>
        explicit message_overflow_exception(T&& message) : logic_error(std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that was caused by active socket read error.
     */
    class socket_read_exception : public active_socket_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        socket_read_exception(int code, T&& message) : active_socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that was caused by host name to address translation error.
     */
    class name_to_address_translation_exception : public system_error
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        name_to_address_translation_exception(int code, T&& message) : system_error(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Exception that was caused by active socket write error.
     */
    class socket_write_exception : public active_socket_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        socket_write_exception(int code, T&& message) : active_socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Passive socket preparation error.
     */
    class passive_socket_prepare_exception : public passive_socket_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        passive_socket_prepare_exception(int code, T&& message) : passive_socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Active socket preparation error.
     */
    class active_socket_prepare_exception : public active_socket_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        active_socket_prepare_exception(int code, T&& message) : active_socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Passive socket accept error.
     */
    class socket_accept_exception : public passive_socket_exception
    {
    public:
        /**
         * \brief Exception constructor
         *
         * \param code exception code (errno or last error on Windows)
         * \param message exception message
         */
        template <class T>
        socket_accept_exception(int code, T&& message) : passive_socket_exception(code, std::forward<T>(message)) {}
    };

    /**
     * \brief Base class for all sockets hierarchy.
     */
    class socket
    {
    public:
        operator bool() const noexcept { return m_ok; } ///< checks socket internal state

        socket(const socket&) = delete;
        socket& operator = (const socket&) = delete;

        void close() noexcept; ///< closes socket
        ~socket() { close(); }
    protected:
        bool m_ok; ///< internal state flag
        socket_t m_socket; ///< socket handle
        
        /**
         * \brief Socket handle based constructor
         *
         * Acquired socket handle will be closed automatically on instance destruction (RAII)
         *
         * \param s socket handle
         */
        explicit socket(socket_t s);
    };

    /**
     * \brief Helper structure that is used to check 'triviality' of type.
     *
     * use trivial_type::value bool constant to check 'triviality'.
     *
     * \tparam T type to check
     */
    template <class T>
    struct trivial_type
    {
        static const bool value = false; ///< check result
    };

#ifndef __DOXYGEN__
    template <>
    struct trivial_type<int32_t>
    {
        static const bool value = true;
    };

    template <>
    struct trivial_type<uint32_t>
    {
        static const bool value = true;
    };

    template <>
    struct trivial_type<int64_t>
    {
        static const bool value = true;
    };

    template <>
    struct trivial_type<uint64_t>
    {
        static const bool value = true;
    };

    template <>
    struct trivial_type<double>
    {
        static const bool value = true;
    };

    template <>
    struct trivial_type<char>
    {
        static const bool value = true;
    };
#endif // __DOXYGEN__

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
         * \tparam ConstPtr defines constness of pointer
         *
         * Can't be used on another side, but can be used as callback parameter as context for example.
         * This wrapper can be used even between applications of different bitness.
         */
        template <bool ConstPtr>
        class remote_ptr
        {
        public:

           /**
            * \brief Helper structure that identifies internal pointer type.
            */
            template <bool ConstPointer, typename T>
            struct const_traits
            {
                typedef T* ptr_t; ///< pointer type
            };

#ifndef __DOXYGEN__
            template <typename T>
            struct const_traits<true, T>
            {
                typedef const T* ptr_t;
            };
#endif // __DOXYGEN__

            /**
             * Helper alias that identifies internal pointer type.
             */
            template <bool ConstPointer, typename T>
            using ptr_t = typename const_traits<ConstPointer, T>::ptr_t;

            /**
             * \brief Extracts underlying pointer.
             *
             * \return raw pointer
             */
            ptr_t<ConstPtr, void> get_pointer() const noexcept { return (ptr_t<ConstPtr, void>)(uintptr_t)m_ptr; }
            
            /**
             * \brief Creates wrapper from raw pointer.
             *
             * \param p raw pointer
             */
            explicit remote_ptr(ptr_t<ConstPtr, void> p = nullptr) noexcept : m_ptr((uintptr_t)p) {} ///<
        protected:
            uint64_t m_ptr; ///< pointer bitwise portable storage

            friend class message;
        };

        constexpr size_t get_max_size() const { return msg_max_length; } ///< returns max available message buffer size
        operator bool() const noexcept { return m_ok; } ///< checks message state

        /**
         * \brief Resets internal state to ok.
         */
        void reset_fail_state() noexcept { m_ok = true; }

    protected:
        /**
         * \brief One byte type tags.
         *
         * More complicated types can be built from this primitives. Unused if __MSG_USE_TAGS__ is 0.
         */
        enum class type_tag : uint8_t
        {
            u32 = 0,
            i32,
            u64,
            i64,
            fp64,
            str,
            chr,
            remote_ptr,
            const_remote_ptr,
            blob
        };

#ifdef __MSG_USE_TAGS__
        const char* to_string(type_tag t) noexcept; ///< gets text representation of tag
        constexpr bool is_compatible_tags(type_tag source, type_tag target) noexcept; ///< checks tags deserializing compatibility
#endif //__MSG_USE_TAGS__

        bool m_ok; ///< internal state flag
        
        /**
         * \brief Helper structure that is used to get #type_tag of given type
         */
        template <typename T> 
        struct tag_traits;

        template <typename T>
        friend struct tag_traits;

        message() noexcept : m_ok(true) {}
        message(const message&) = delete;
        message& operator=(const message&) = delete;

        /**
         * \brief Gets ipc::remote_ptr<ConstPtr> internal storage value.
         *
         * \param p remote pointer object
         */
        template <bool ConstPtr>
        uint64_t get_u64_ptr(const remote_ptr<ConstPtr>& p) const noexcept { return p.m_ptr; }

        /**
         * \brief Gets ipc::remote_ptr<ConstPtr> internal storage reference.
         *
         * \param p remote pointer object
         */
        template <bool ConstPtr>
        uint64_t& get_u64_ptr(remote_ptr<ConstPtr>& p) noexcept { return p.m_ptr; }
    };

    /**
     * \brief Output message type.
     *
     * This class serializes user's data to its internal buffer which max size is __MSG_MAX_LENGTH__.
     * Filled message should be passed to PointToPointSocket::write_message function.
     */
    class out_message : public message
    {
    public:
        /**
         * \brief Serializes user's data of trivial type to internal buffer.
         * 
         * \param arg - data to serialize.
         *
         * \return message self reference 
         */
        template <typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        out_message& operator << (T arg) { return push<tag_traits<T>::value>(arg); }

        /**
         * \brief Serializes user's data of string type (std::string, const char*, std::string_view) to internal buffer.
         * 
         * \param s - string to serialize.
         *
         * \return message self reference 
         */
        out_message& operator << (const std::string_view& s);
        
        /**
         * \brief Serializes user's pointer to internal buffer.
         * 
         * \param p - pointer to serialize.
         *
         * \return message self reference 
         */
        template <bool ConstPtr>
        out_message& operator << (const remote_ptr<ConstPtr>& p) { return push<ConstPtr ? type_tag::const_remote_ptr : type_tag::remote_ptr>(get_u64_ptr(p)); }
        
        /**
         * \brief Serializes user's blob to internal buffer.
         * 
         * \param blob - blob to serialize.
         *
         * \return message self reference 
         */
        out_message& operator << (const std::pair<const uint8_t*, size_t>& blob);
        
        /**
         * \brief Resets message to empty state.
         */
        void clear() noexcept; 
        
        /**
         * \brief Default constructor
         *
         * Allocates buffer of minimal available size and clears object state.
         */
        out_message() { clear(); }
        
        /**
         * \brief Returns underlying data buffer.
         */
        const std::vector<char>& get_data() const noexcept { return m_buffer; }
        
    protected:
        /**
          * \brief Serializes user's data of trivial type to internal buffer with custo tag.
          *
          * \param arg - data to serialize.
          */
        template <type_tag Tag, typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        out_message& push(T arg);
        
        std::vector<char> m_buffer; ///< internal message buffer
    };

    /**
     * \brief Input message type.
     *
     * This class deserializes user data from its internal buffer which max size is __MSG_MAX_LENGTH__.
     * Empty message should be filled by PointToPointSocket::read_message function first.
     */
    class in_message : public message
    {
    public:
        /**
         * \brief Deserializes data of trivial type from internal buffer.
         * 
         * \param arg - extracted data.
         *
         * \return message self reference 
         */
        template <typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        in_message& operator >> (T& arg) { return pop<tag_traits<T>::value>(arg); }

        /**
         * \brief Deserializes string data from internal buffer.
         * 
         * \param arg - extracted data.
         *
         * \return message self reference 
         */
        in_message& operator >> (std::string& arg);
        
        /**
         * \brief Deserializes remote pointer from internal buffer.
         * 
         * \param p - extracted pointer.
         *
         * \return message self reference 
         */
        template <bool ConstPtr>
        in_message& operator >> (remote_ptr<ConstPtr>& p) { return pop<ConstPtr ? type_tag::const_remote_ptr : type_tag::remote_ptr>(get_u64_ptr(p)); }
        
        /**
         * \brief Deserializes blob from internal buffer.
         * 
         * \param blob - extracted data.
         *
         * \return message self reference 
         */
        in_message& operator >> (std::vector<uint8_t>& blob);

        /**
         * \brief Deserializes blob from internal buffer. This version can be more performance efficient than previous one.
         * 
         * \param blob - extracted data. Array (first member of pair) must be long enough to store blob, second member will hold real blob size.
         *
         * \return message self reference 
         */
        template <size_t N>
        in_message& operator >> (std::pair<std::array<uint8_t, N>, size_t>& blob);
        
        /**
         * \brief Resets message to empty state.
         */
        void clear() noexcept;
        
        /**
         * \brief Default constructor
         *
         * Allocates buffer of max available size and clears object state.
         */
        in_message() : m_buffer(get_max_size()) { clear(); }
        
        /**
         * \brief Returns underlying data buffer.
         */
        std::vector<char>& get_data() noexcept { return m_buffer; }

    protected:
        /**
         * \brief Deserializes data of trivial type from internal buffer (with custom tag checking).
         * 
         * \param arg - extracted data.
         */
        template <type_tag Tag, typename T, typename = std::enable_if_t<trivial_type<T>::value>>
        in_message& pop(T& arg);

        std::vector<char> m_buffer; ///< internal message buffer
        size_t m_offset; ///< current reading offset in #m_buffer
    };

    class server_socket;

    /**
     * \brief Bidirectional data channel.
     *
     * This class allows pair of applications to send and receive data between each other. Instance cannot be created directly:
     * it can be obtained as result of ServerSocket::accept (received instance will represent server side of data channel).
     */
    class point_to_point_socket : public socket
    {
    public:
        /**
         * \brief Reads raw message from channel. Use it only if you really need raw message form.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function 
         * will immediately return false and state of message will be invalid and must be reset.
         *
         * \param message raw message buffer (length and data, see ipc::Message)
         * \param predicate function of type bool() or similar callable object 
         *
         * \return true if message has been read successfully.
         */
        template<typename Predicate>
        bool read_message(std::vector<char>& message, const Predicate& predicate);

        /**
         * \brief Reads message from channel.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function 
         * will immediately return false and state of message will be invalid and must be reset.
         *
         * \param message message object
         * \param predicate function of type bool() or similar callable object 
         *
         * \return true if message has been read successfully.
         */
        template<typename Predicate>
        bool read_message(in_message& message, const Predicate& predicate);

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
          *
          * \return true if message writing has been started successfully
          */
        template<typename Predicate>
        bool write_message(const char * message, const Predicate& predicate);

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
          *
          * \return true if message writing has been started successfully
          */
        template<typename Predicate>
        bool write_message(out_message& message, const Predicate& predicate) { return write_message(message.get_data().data(), predicate); }

        /**
          * \brief Waits for shutdown signal.
          *          
          * \p predicate may be called several times to ask if the function should continue waiting for signal. If \p predicate returns false function 
          * will immediately return.
          *
          * \param predicate function of type bool() or similar callable object 
          *
          * \sa #shutdown.
          */
        template<typename Predicate>
        void wait_for_shutdown(const Predicate& predicate);

        /**
          * \brief Sends shutdown signal.
          *
          * \sa #wait_for_shutdown.
          */
        void shutdown() noexcept;

        ~point_to_point_socket() { shutdown(); }
    protected:
        typedef socket super; ///< super class typedef

        /**
         * \brief Socket handle based constructor
         *
         * Acquired socket handle will be closed automatically (#shutdown will be called before it) on instance destruction (RAII)
         *
         * \param s socket handle
         */
        explicit point_to_point_socket(socket_t s) noexcept : socket(s) {}

        friend class server_socket;
    };

    /**
     * \brief Helper class for building client sockets.
     */
    class client_socket : public point_to_point_socket
    {
    protected:
        /**
         * \brief Socket handle based constructor. Just forwards \p s to ipc::point_to_point_socket constructor.
         *
         * \param s socket handle
         */
        explicit client_socket(socket_t s) noexcept : point_to_point_socket(s) {}

        /**
         * \brief Establishes connection to the server
         *
         * \param address filled sockaddr compatible structure
         * \param size size of structure pointed by address
         */
        void connect_proc(const sockaddr* address, size_t size);
    };

    /**
     * \brief Client side of bidirectional data channel based on TCP sockets.
     */
    class tcp_client_socket : public client_socket
    {
    public:
        /**
          * \brief Tries to connect to TCP with \p port.
          *
          * \param address server IP address
          * \param port TCP port number
          */
        tcp_client_socket(uint32_t address, uint16_t port);

        /**
         * \brief Tries to connect to TCP with \p port.
         *
         * \param address server IP address (null termination is required)
         * \param port TCP port number
         */

        tcp_client_socket(std::string_view address, uint16_t port);

    private:
        void connect_proc(uint32_t address, uint16_t port);

        typedef client_socket super; ///< super class typedef
    };

#ifdef __AFUNIX_H__
    /**
     * \brief Client side of bidirectional data channel based on UNIX sockets.
     * 
     * \warning Unix sockets available on Windows only since Windows 10 build 17063
     */
    class unix_client_socket : public client_socket
    {
    public:
        /**
          * \brief Tries to connect to UNIX socket \p path.
          *      
          * \param path UNIX socket path (must be null terminated)
          */
        explicit unix_client_socket(std::string_view path);

    private:
        typedef client_socket super; ///< super class typedef
    };
#endif //__AFUNIX_H__

    /**
     * \brief Common passive (listening) socket. Helper class only.
     */
    class server_socket : public socket
    {
    public:
        /**
         * \brief Waits for incoming connections. 
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for incoming connections. If \p predicate returns false function 
         * will immediately throw ipc::user_stop_request_exception. 
         *
         * \param predicate function of type bool() or similar callable object 
         * \return socket for data exchange
         */
        template<typename Predicate>
        point_to_point_socket accept(const Predicate& predicate);
    protected:
        /**
        * \brief Default constructor
        *
        * Creates server socket instance that initialized by INVALID_SOCKET
        */
    
        server_socket() noexcept : socket(INVALID_SOCKET) {}

        std::mutex m_lock; ///< mutex for accept requests synchronizing

        /**
         * \brief Binds socket handle to the address
         * 
         * \param address address to bind
         * \param size size of data that \p address points
         */
        void bind_proc(const sockaddr* address, size_t size);
    };

#ifdef __AFUNIX_H__
   /**
     * \brief Unix passive (listening) socket.
     * 
     * \warning Unix sockets available on Windows only since Windows 10 build 17063
     */
    class unix_server_socket : public server_socket
    {
    public:
        /**
         * \brief Tries to create UNIX socket \p path. 
         *      
         * \param path UNIX socket path
         */
        explicit unix_server_socket(std::string_view path);
        
        ~unix_server_socket() { close(); };
        void close() noexcept; ///< closes socket
    protected:
        typedef server_socket super; ///< super class typedef
        std::string m_link; ///< server text identifier
    };
#endif //__AFUNIX_H__

    /**
     * \brief TCP passive (listening) socket.
     */
    class tcp_server_socket : public server_socket
    {
    public:
        /**
         * \brief Tries to create TCP socket that will listen \p port.
         *
         * \param port TCP port number
         */
        explicit tcp_server_socket(uint16_t port);
    };
}

#ifndef __DOXYGEN__
#include "../source/ipc_impl.hpp"
#endif // __DOXYGEN__

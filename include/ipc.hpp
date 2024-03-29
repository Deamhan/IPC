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
#include <cinttypes>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
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
#   include "alpc.h"
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
     * \brief Received data validation error
     */
    class validation_error : public logic_error
    {
    public:
       /**
        * \brief Exception constructor
        * 
        * \param message exception message
        */
        template <class T>
        validation_error(T&& message) : logic_error(std::forward<T>(message)) {}
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
     *
     * \tparam Engine Default or custom low level API provider
     */
    template <class Engine>
    class socket
    {
    public:
        operator bool() const noexcept { return m_engine.is_ok(); } ///< checks socket internal state

        socket(const socket&) = delete;
        socket& operator = (const socket&) = delete;

        void close() noexcept { m_engine.close(); }; ///< closes socket
        ~socket() { close(); }

    protected:
        Engine m_engine; ///< all low level work is done by engine
        
        /**
         * \brief Socket handle based constructor
         *
         * Acquired socket handle will be closed automatically on instance destruction (RAII)
         *
         */
        template <class... Args>
        explicit socket(Args&&... args) : m_engine(std::forward<Args>(args)...) {}
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
            template <bool ConstPointer, class T>
            struct const_traits
            {
                typedef T* ptr_t; ///< pointer type
            };

#ifndef __DOXYGEN__
            template <class T>
            struct const_traits<true, T>
            {
                typedef const T* ptr_t;
            };
#endif // __DOXYGEN__

            /**
             * Helper alias that identifies internal pointer type.
             */
            template <bool ConstPointer, class T>
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
        template <class T>
        struct tag_traits;

        template <class T>
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
     * Filled message should be passed to point_to_point_socket::write_message function.
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
        template <class T, class = std::enable_if_t<trivial_type<T>::value>>
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
        template <type_tag Tag, class T, class = std::enable_if_t<trivial_type<T>::value>>
        out_message& push(T arg);
        
        std::vector<char> m_buffer; ///< internal message buffer
    };

    /**
     * \brief Input message type.
     *
     * This class deserializes user data from its internal buffer which max size is __MSG_MAX_LENGTH__.
     * Empty message should be filled by point_to_point_socket::read_message function first.
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
        template <class T, class = std::enable_if_t<trivial_type<T>::value>>
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
        template <type_tag Tag, class T, class = std::enable_if_t<trivial_type<T>::value>>
        in_message& pop(T& arg);

        std::vector<char> m_buffer; ///< internal message buffer
        size_t m_offset; ///< current reading offset in #m_buffer
    };

    template <class Engine>
    class server_socket;

    /**
     * \brief Helper class for implementing bidirectional data sockets.
     */
    template <class Engine>
    class point_to_point_socket : public socket<Engine>
    {
    public:
        /**
         * \brief Waits for shutdown signal.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for signal. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception.
         *
         * \param predicate function of type bool() or similar callable object
         *
         * \sa #shutdown.
         */
        template<class Predicate>
        void wait_for_shutdown(const Predicate& predicate) { this->m_engine.wait_for_shutdown(predicate, 1); }

        /**
         * \brief Sends shutdown signal.
         *
         * \sa #wait_for_shutdown.
         */
        void shutdown() noexcept { this->m_engine.shutdown(); };

        ~point_to_point_socket() { shutdown(); }
    protected:
        typedef socket<Engine> super; ///< super class typedef

        /**
         * \brief Socket handle based constructor
         *
         * Acquired socket handle will be closed automatically (#shutdown will be called before it) on instance destruction (RAII)
         *
         * \param s socket handle
         */
        template <class... Args>
        explicit point_to_point_socket(Args&&... args) : socket<Engine>(std::forward<Args>(args)...) {}

        template <class T>
        friend class server_socket;
    };

    /**
     * \brief Active (data) server socket
     *
     * This class allows server to communicate with particular client. Instance cannot be created directly:
     * it can be obtained as result of server_socket::accept (received instance will represent server side of data channel).
     */
    template <class Engine>
    class server_data_socket : public point_to_point_socket<Engine>
    {
    public:
        template <class... Args>
        explicit server_data_socket(Args&&... args) noexcept : point_to_point_socket<Engine>(std::forward<Args>(args)...) {}

        /**
         * \brief Reads raw message from channel. Use it only if you really need raw message form.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception and state of message will be invalid and must be reset.
         *
         * \param message raw message buffer (length and data, see ipc::message)
         * \param predicate function of type bool() or similar callable object
         *
         * \return true if message has been read successfully.
         */
        template<class Predicate>
        void get_request(std::vector<char>& message, const Predicate& predicate);

        /**
         * \brief Reads message from channel.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception and state of message will be invalid and must be reset.
         *
         * \param message message object
         * \param predicate function of type bool() or similar callable object
         *
         * \return true if message has been read successfully.
         */
        template<class Predicate>
        void get_request(in_message& message, const Predicate& predicate);

        /**
          * \brief Writes raw message to channel. Use it only if you really need raw message form.
          *
          * \p predicate may be called several times to ask if the function should continue trying to write data. If \p predicate returns false function
          * will throw an ipc::user_stop_request_exception and data will not be written.
          *
          * \warning because of non blocking writing data may not be written immediatelly after function exit, so it is recommended to wait for some kind
          * of answer from another side and only after that destroy \p message.
          *
          * \param message object
          * \param predicate function of type bool() or similar callable object
          *
          * \return true if message writing has been started successfully
          */
        template<class Predicate>
        void send_response(const char* message, const Predicate& predicate);

        /**
          * \brief Writes message to channel.
          *
          * \p predicate may be called several times to ask if the function should continue trying to write data. If \p predicate returns false function
          * will throw an ipc::user_stop_request_exception and data will not be written.
          *
          * \warning because of non blocking writing data may not be written immediatelly after function exit, so it is recommended to wait for some kind
          * of answer from another side and only after that destroy \p message.
          *
          * \param message object
          * \param predicate function of type bool() or similar callable object
          *
          * \return true if message writing has been started successfully
          */
        template<class Predicate>
        void send_response(out_message& message, const Predicate& predicate) { return send_response(message.get_data().data(), predicate); }
    };

    /**
     * \brief Active (data) socket
     */
    template <class Engine>
    class client_socket : public point_to_point_socket<Engine>
    {
    public:
        /**
         * \brief Socket handle based constructor. Just forwards \p s to ipc::point_to_point_socket constructor.
         *
         * \param s socket handle
         */
        template <class... Args>
        explicit client_socket(Args&&... args) : point_to_point_socket<Engine>(std::forward<Args>(args)...) {}

        /**
         * \brief Sends and receives raw messages from channel. Use it only if you really need raw message form.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data of finishing writing. 
         * If \p predicate returns false function will throw an ipc::user_stop_request_exception and state of message will be invalid and must be reset.
         *
         * \param request raw message buffer (length and data, see ipc::message) that contains request data
         * \param response raw message buffer that contains response data
         * \param predicate function of type bool() or similar callable object 
         *
         * \return true if message has been read successfully.
         */
        template<class Predicate>
        void send_request(const char* request, std::vector<char>& response, const Predicate& predicate);

        /**
         * \brief Sends and receives messages from channel.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data of finishing writing. 
         * If \p predicate returns false function will throw an ipc::user_stop_request_exception and state of message will be invalid and must be reset.
         *
         * \param request message that contains request data
         * \param response message that contains response data
         * \param predicate function of type bool() or similar callable object 
         *
         * \return true if message has been read successfully.
         */
        template<class Predicate>
        void send_request(out_message& request, in_message& response, const Predicate& predicate);
    };

    /**
     * \brief Passive (listening) socket
     */
    template <class Engine>
    class server_socket : public socket<Engine>
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
        template<class Predicate>
        server_data_socket<typename Engine::point_to_point_engine_t> accept(const Predicate& predicate);

        /**
        * \brief Default constructor
        *
        * Creates server socket instance
        */
        template <class... Args>
        server_socket(Args&&... args) : socket<Engine>(std::forward<Args>(args)...) {}
    };

    /**
     * \brief Base class for socket based engines
     */
    class os_socket_engine
    {
    public:
        bool& is_ok() noexcept { return m_ok; } ///< read/write status access method
        void close() noexcept; ///< closes socket

    protected:
        bool m_ok; ///< socket status member
        socket_t m_socket; ///< socket handle

        os_socket_engine(socket_t s);
    };

    /**
     * \brief Engine that implements bidirectional data communication channel (active socket)
     */
    class os_point_to_point_socket_engine : public os_socket_engine
    {
    public:
        /**
         * \brief Reads data from channel.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception.
         *
         * \param message raw message buffer
         * \param size raw message buffer size
         * \param predicate function of type bool() or similar callable object
         * \param timeout_sec timeout in seconds (after each timeout \p predicate will be called)
         *
         * \return read bytes count.
         */
        template<class Predicate>
        size_t read(char* message, size_t size, const Predicate& predicate, uint16_t timeout_sec);

        /**
         * \brief Writes data from channel.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for data. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception.
         *
         * \param message raw message buffer (size and data, see ipc::message)
         * \param predicate function of type bool() or similar callable object
         * \param timeout_sec timeout in seconds (after each timeout \p predicate will be called)
         *
         * \return wring status.
         */
        template<class Predicate>
        bool write(const char* message, const Predicate& predicate, uint16_t timeout_sec);

        /**
         * \brief Sends shutdown signal.
         *
         * \sa #wait_for_shutdown.
         */
        void shutdown();

        /**
         * \brief Waits for shutdown signal.
         *
         * \p predicate may be called several times to ask if the function should continue waiting for signal. If \p predicate returns false function
         * will throw an ipc::user_stop_request_exception.
         *
         * \param predicate function of type bool() or similar callable object
         *
         * \sa #shutdown.
         */
        template<class Predicate>
        void wait_for_shutdown(const Predicate& predicate, uint16_t timeout_sec);

        os_point_to_point_socket_engine(socket_t s) : os_socket_engine(s) {}
    };

    /**
     * \brief Engine that implements generic passive socket (listener). It is helper class only.
     */
    class os_server_socket_engine : public os_socket_engine
    {
    public:
        /**
         * \brief Waits for incoming connections. 
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for incoming connections. If \p predicate returns false function 
         * will throw ipc::user_stop_request_exception. 
         *
         * \param predicate function of type bool() or similar callable object 
         * \return data exchange socket handle
         */
        template<class Predicate>
        socket_t accept(const Predicate& predicate, uint16_t timeout_sec);

        /**
         * \brief Related engine for server_data_socket.
         */
        typedef os_point_to_point_socket_engine point_to_point_engine_t;

    protected:
        std::mutex m_lock; ///< mutex for accept synchronization

        void bind_proc(const sockaddr* address, size_t size); ///< helper routine for socket binding
        os_server_socket_engine(socket_t s): os_socket_engine(s) {}
    };

    /**
     * \brief Engine that implements client bidirectional data communication channel.
     */
    class client_socket_engine : public os_point_to_point_socket_engine
    {
    public:
        client_socket_engine(socket_t s) : os_point_to_point_socket_engine(s) {}

        /**
         * \brief Sends and receives data from channel.
         *          
         * \p predicate may be called several times to ask if the function should continue waiting for data of finishing writing. 
         * If \p predicate returns false function will throw an ipc::user_stop_request_exception.
         *
         * \param request raw message buffer (length and data, see ipc::message) that contains request data
         * \param response raw message buffer that contains response data
         * \param predicate function of type bool() or similar callable object 
         *
         * \return true if message has been read successfully.
         */
        template<class Predicate>
        void send_request(const char* request, char* response, size_t response_size, const Predicate& predicate, uint16_t timeout_sec)
        {
            write(request, predicate, timeout_sec);
            read(response, response_size, predicate, timeout_sec);
        }
    
    protected:
        void connect_proc(const sockaddr* address, size_t size); ///< helper routine for server connection
    }; 

#ifdef __AFUNIX_H__
    /**
     * \brief Engine that implements UNIX passive socket (listener). 
     *
     * UNIX socket used for local interprocess communication, filesystem node is used like a port.
     * This types of sockets are available on windows since build 17063. It is used by WSL.
     */
    class unix_server_socket_engine final : public os_server_socket_engine
    {
    public:
        /**
         * \brief UNIX socket engine constructor. 
         *
         * \param filesystem path to bind socket on it
         */
        unix_server_socket_engine(std::string_view socket_link);
        void close() noexcept;

    private:
        std::string m_link;
        typedef os_socket_engine super;
    };

    /**
     * \brief Engine that implements UNIX client socket.
     */
    class unix_client_socket_engine final : public client_socket_engine
    {
    public:
        /**
         * \brief UNIX socket engine constructor. 
         *
         * \param filesystem path to bind socket on it
         */
        unix_client_socket_engine(std::string_view socket_link);

    private:
        std::string m_link; ///< path to file that used by UNIX server socket
    };

    typedef server_socket<unix_server_socket_engine> unix_server_socket;
    typedef client_socket<unix_client_socket_engine> unix_client_socket;
#endif //__AFUNIX_H__

#ifdef __VSOCK__
    /**
     * \brief Engine that implements virtual machines <-> hypervisor passive socket (listener). 
     *
     * Hyper-V/WSL2 AF_HYPERV case is used on Windows (only this cases are tested)
     */
    class virtual_server_socket_engine final : public os_server_socket_engine
    {
    public:
#   ifdef _WIN32
        /**
         * \brief Virtual socket engine constructor. 
         *
         * \param vm_id - virtual machine ID (GUID on Windows (Hyper-V), unsigned int on Linux)
         * \param service_id - service ID (GUID on Windows (Hyper-V), unsigned int on Linux), used like TCP/UDP port
         */
        virtual_server_socket_engine(const wchar_t* vm_id, const wchar_t* service_id);
#   elif defined (__linux__)
        virtual_server_socket_engine(unsigned vm_id, unsigned service_id);
#   endif

    private:
        typedef os_socket_engine super; ///< parent class
    };

    /**
     * \brief Engine that implements virtual machines <-> hypervisor client socket. 
     *
     * Hyper-V/WSL2 AF_HYPERV case is used on Windows (only this cases are tested)
     */
    class virtual_client_socket_engine final : public client_socket_engine
    {
    public:
#   ifdef _WIN32
        /**
         * \brief Virtual socket engine constructor. 
         *
         * \param vm_id - virtual machine ID (GUID on Windows (Hyper-V), unsigned int on Linux)
         * \param service_id - service ID (GUID on Windows (Hyper-V), unsigned int on Linux), used like TCP/UDP port
         */
        virtual_client_socket_engine(const wchar_t* vm_id, const wchar_t* service_id);
#   elif defined (__linux__)
        virtual_client_socket_engine(unsigned vm_id, unsigned service_id);
#   endif
    };

    typedef server_socket<virtual_server_socket_engine> virtual_server_socket;
    typedef client_socket<virtual_client_socket_engine> virtual_client_socket;
#endif // __VSOCK__

    /**
     * \brief Engine that implements TCP/IP passive socket (listener). 
     *
     * Most cross platform engine, must work on any popular platform.
     */
    class tcp_server_socket_engine final : public os_server_socket_engine
    {
    public:
        /**
         * \brief TCP/IP socket engine constructor. 
         *
         * \param port - TCP port to bind
         */
        tcp_server_socket_engine(uint16_t port);
    };

    /**
     * \brief Engine that implements TCP/IP active (data) socket. 
     */
    class tcp_client_socket_engine final : public client_socket_engine
    {
    public:
        /**
         * \brief TCP/IP socket engine constructor. 
         *
         * \param address - IPv4 address to connect
         * \param port - TCP port to connect
         */
        tcp_client_socket_engine(uint32_t address, uint16_t port);
        
        /**
         * \brief TCP/IP socket engine constructor. 
         *
         * \param name - symbolic name to connect
         * \param port - TCP port to connect
         */
        tcp_client_socket_engine(std::string_view name, uint16_t port);

    private:
        void connect_proc(uint32_t address, uint16_t port);
        typedef client_socket_engine super;
    };

    typedef server_socket<tcp_server_socket_engine> tcp_server_socket;
    typedef client_socket<tcp_client_socket_engine> tcp_client_socket;

#if defined(_WIN32) && defined(USE_ALPC)
    class alpc_engine
    {
    public:
        void close() noexcept;
        ~alpc_engine() { close(); }
        bool& is_ok() noexcept { return m_ok; }

    protected:
        HANDLE m_alpc_port;
        bool m_ok;

        alpc_engine(HANDLE alpc_port) noexcept: m_alpc_port(alpc_port), m_ok(true) {}
    };

    class alpc_point_to_point_connection_engine : public alpc_engine
    {
    public:
        void shutdown() noexcept { close(); }

        template<class Predicate>
        void wait_for_shutdown(const Predicate& predicate, uint16_t timeout_sec) noexcept {}

        alpc_point_to_point_connection_engine(HANDLE alpc_port) noexcept : alpc_engine(alpc_port) {}
    };

    class alpc_client_engine : public alpc_point_to_point_connection_engine
    {
    public:
        alpc_client_engine(const wchar_t* port_name);
        
        template<class Predicate>
        void send_request(const char* request, char* response, size_t response_size, const Predicate& predicate, uint16_t timeout_sec);

    private:
        std::vector<char> m_buffer;
    };

    class blocking_slot
    {
    public:
        void push(PPORT_MESSAGE msg);
        bool try_push(PPORT_MESSAGE msg);
        bool pop(char* buffer, size_t size, uint32_t seconds);
        void push_with_exception_saving(PPORT_MESSAGE msg);

        blocking_slot() : m_push_flag(true), m_pop_flag(false), m_buffer(msg_max_length + sizeof(PORT_MESSAGE))
        {}

    private:
        std::condition_variable m_push_cv;
        std::condition_variable m_pop_cv;
        bool m_push_flag;
        bool m_pop_flag;
        std::mutex m_lock;

        std::vector<char> m_buffer;
        std::exception_ptr m_saved_exception;

        void push(PPORT_MESSAGE msg, std::unique_lock<std::mutex>& lm);
    };

    struct alpc_connection
    {
        blocking_slot m_slot;
        HANDLE m_connection_handle;
        std::vector<char> m_buffer;

        alpc_connection(HANDLE connection) : m_connection_handle(connection), m_buffer(msg_max_length + sizeof(PORT_MESSAGE)) {}
    };

    class alpc_server_data_engine : public alpc_point_to_point_connection_engine
    {
    public:
        template<class Predicate>
        size_t read(char* message, size_t size, const Predicate& predicate, uint16_t timeout_sec);

        template<class Predicate>
        void write(const char* message, const Predicate& predicate, uint16_t timeout_sec);

    private:
        std::unique_ptr<alpc_connection> m_connection;
        ULONG m_id;
        std::vector<char> m_buffer;
        alpc_server_data_engine(alpc_connection* connection) noexcept : alpc_point_to_point_connection_engine(connection->m_connection_handle), 
            m_connection(connection), m_id(0), m_buffer(msg_max_length + sizeof(PORT_MESSAGE)) {}

        friend class socket<alpc_server_data_engine>;
    };

    class alpc_server_engine : public alpc_engine
    {
    public:
        alpc_server_engine(const wchar_t* port_name);

        typedef alpc_server_data_engine point_to_point_engine_t;

        template<class Predicate>
        alpc_connection* accept(const Predicate& predicate, uint16_t timeout_sec);

        ~alpc_server_engine();

    private:
        std::thread m_listener;
        void listen_proc();
        std::atomic<bool> m_stop_signal;

        std::vector<char> m_buffer;
        char m_attr_buffer[64];

        blocking_slot m_accept_slot;
    };
#endif // _WIN32 && USE_ALPC
    
}

#ifndef __DOXYGEN__
#include "../source/ipc_impl.hpp"
#endif // __DOXYGEN__

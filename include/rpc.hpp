/**
 * \file rpc.hpp
 *
 * \brief Additional IPC library components (RPC). 
 *
 * \copyright Copyright (C) 2020 Pavel Kovalenko. All rights reserved.<br>
 * <br>
 * This Source Code Form is subject to the terms of the Mozilla<br>
 * Public License, v. 2.0. If a copy of the MPL was not distributed<br>
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#ifndef __DOXYGEN__
#include  <thread>
#endif // __DOXYGEN__

#include "ipc.hpp"

namespace ipc
{
    /**
     * \brief Helper class to hold constants of function_invoker template.
     */
    class function_invoker_base
    {
    public:
        static const uint32_t done_tag = 0xFFFFFFFFu; ///< final result marker, greatest uint32_t value
    protected:
        function_invoker_base() = default;
    };

    /**
     * \brief Lightweight native function call helper.
     * 
     * This class takes care about native function arguments deserializing, function (or function-like object) call and result serializing. Native function arguments types must have serializable types.
     *
     * \tparam Function_type function prototype, for example int32_t(std::string, uint32_t, ipc::message::remote_ptr<true>), const reference modifiers will be removed
     * \tparam Use_done_tag set it to true if you want to set ipc::function_invoker_base::done_tag in the begin of result message (it can be used to interrupt client callback processing loop)
     */
    template <typename Function_type, bool Use_done_tag>
    class function_invoker;

    /**
     * \brief Lightweight native function call helper.
     * 
     * This class takes care about native function arguments deserializing, function (or function-like object) call and result serializing. Native function arguments types must have serializable types.
     *
     * \tparam Use_done_tag set it to true if you want to set ipc::function_invoker_base::done_tag in the begin of result message (it can be used to interrupt client callback processing loop)
     * \tparam R return value type, const reference modifiers will be removed
     * \tparam Args function (or function-like object) arguments types, const reference modifiers will be removed
     */
    template <bool Use_done_tag, typename R, typename... Args>
    class function_invoker<R(Args...), Use_done_tag> : public function_invoker_base
    {
    public:
        /**
         * \brief Calls native function.
         *
         * \param in_msg message with input data (arguments)
         * \param out_msg message for result
         * \param func function or function-like object to call
         */
        template <typename Func>
        void operator()(in_message& in_msg, out_message& out_msg, Func&& func);
    };

    /**
     * \brief Lightweight remote service call helper.
     */
    class service_invoker
    {
    public:
        /**
         * \brief Calls remote service by text link.
         * 
         * Esteblishes remote connection, serializes data and recieves result.
         *
         * \tparam Id identifier of remote function
         * \tparam R return value type
         * \param address service address (unix socket path or address and port to TCP connection)
         * \param dispatcher dispatcher routine (or function-like object) compatible with bool(uint32_t id, ipc::in_message& in_msg, ipc::out_message& out_msg). This function should return true if known 
         *  callback id is got, false otherwise
         * \param predicate function of type bool() or similar callable object 
         * \param args remote service arguments
         *
         * \return result of remote call
         */
        template <uint32_t Id, class R, typename Tuple, class Dispatcher, class Predicate, class... Args>
        R call_by_address(const Tuple& address, Dispatcher& dispatcher, const Predicate& predicate, const Args&... args);

        /**
         * \brief Calls remote service by established connection.
         * 
         * Serializes data and recieves result.
         *
         * \tparam Id identifier of remote function
         * \tparam R return value type
         * \param socket established connection
         * \param in_msg input message
         * \param out_msg output message
         * \param predicate function of type bool() or similar callable object 
         * \param args remote service arguments
         *
         * \return result of remote call
         */
        template <uint32_t Id, class R, class Predicate, class Engine, class... Args>
        R call_by_channel(point_to_point_socket<Engine>& socket, in_message& in_msg, out_message& out_msg, const Predicate& predicate, const Args&... args);
    };

    /**
     * \brief Thread pool and sockets handler
     *
     * \tparam Server_socket sorver socket class that will be used by RPC server
     *
     * This class takes care about thread pool creating, connections and messages handling.
     */
    template <typename Server_socket>
    class rpc_server
    {
    public:
        /**
         * \brief Creates remote procedure call handling server.
         *
         * \param args info for socket creation
         */
        template <typename... Args>
        explicit rpc_server(const Args&... args) : m_server_socket(args...) {}

        /**
         * \brief Enables remote calls processing.
         *
         * This routine creates and runs thread pool workers, each of them accepts and processes incoming requests. After successful running of workers Dispatcher::ready callback will be called.
         *
         * \param dispatcher object that must have several methods:  invoke(uint32_t, ipc::in_message&, ipc::out_message&, ipc::point_to_point_socket&) const, void report_error(const std::exception&) const and void ready() const.
         * \param predicate predicate function (or function-like object) that allows user to stop worker threads.
         */
        template <typename Dispatcher, typename Predicate>
        void run(const Dispatcher& dispatcher, const Predicate& predicate);

    protected:
        Server_socket m_server_socket; ///< passive socket channel instance

        /**
         * \brief Thread pool worker routine.
         *
         * This routine accepts incomming connections, reads incoming messages, deserializes request code and forwars it to Dispatcher::invoke routine (in loop). After dispatching outcoming message will be sent back by #thread_proc.
         * #thread_proc sets top level exception handler that forwards exceptions to Dispatcher::report_error as std::exception referenses. 
         *
         * \param dispatcher object that must have several methods:  invoke(uint32_t, ipc::in_message&, ipc::out_message&, ipc::point_to_point_socket&) const, void report_error(const std::exception_ptr& p) const and void ready() const.
         * \param predicate predicate function (or function-like object) that allows user to stop worker threads.
         */
        template <typename Dispatcher, typename Predicate>
        void thread_proc(const Dispatcher* dispatcher, const Predicate* predicate);
    };
}

#ifndef __DOXYGEN__
#include "../source/rpc_impl.hpp"
#endif // __DOXYGEN__

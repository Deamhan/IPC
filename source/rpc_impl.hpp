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

#include <algorithm>
#include <exception>

#include "../include/rpc.hpp"

namespace ipc
{
    template <typename Server_socket> template <typename Dispatcher, typename Predicate>
    inline void rpc_server<Server_socket>::run(const Dispatcher& dispatcher, const Predicate& predicate)
    {
        std::vector<std::thread> workers;
        std::generate_n(std::back_inserter(workers), std::thread::hardware_concurrency(), [this, &dispatcher, &predicate]
            { 
                return std::thread(&rpc_server::thread_proc<Dispatcher, Predicate>, this, &dispatcher, &predicate);
            });
    
        dispatcher.ready();

        for (auto& worker : workers)
            worker.join();
    }
    
    template <typename Server_socket> template <typename Dispatcher, typename Predicate>
    inline void rpc_server<Server_socket>::thread_proc(const Dispatcher* d, const Predicate* predicate)
    {
        in_message in_msg;
        out_message out_msg;
    
        while ((*predicate)())
        {
            try
            {
                auto connection_socket = m_server_socket.accept(*predicate);
                connection_socket.get_request(in_msg, *predicate);
    
                uint32_t function = 0;
                in_msg >> function;
                d->invoke(function, in_msg, out_msg, connection_socket);
                connection_socket.send_response(out_msg, *predicate);
                connection_socket.wait_for_shutdown(*predicate);
            }
            catch (...)
            {
                std::exception_ptr p = std::current_exception();
                d->report_error(p);
            }
        }
    }
    
    template <typename Tuple, size_t... I>
    static inline void input_tuple([[maybe_unused]] in_message& msg, [[maybe_unused]] Tuple& t, std::index_sequence<I...>)
    {
        if constexpr (sizeof...(I) != 0)
            (msg >> ... >> std::get<I>(t));
    }
    
    template <bool Use_done_tag, typename R, typename... Args> template <typename Func>
    inline void function_invoker<R(Args...), Use_done_tag>::operator()(in_message& in_msg, out_message& out_msg, Func&& func)
    {
        std::tuple<std::remove_reference_t<std::remove_cv_t<Args>>...> args;
        input_tuple(in_msg, args, std::make_index_sequence<sizeof...(Args)>{});
        out_msg.clear();
        if constexpr (!std::is_same_v<R, void>)
        {
            R result = std::apply(std::forward<Func>(func), std::move(args));
            if constexpr (Use_done_tag)
                out_msg << done_tag;
            out_msg << result;
        }
        else
        {
            std::apply(std::forward<Func>(func), std::move(args));
            if constexpr (Use_done_tag)
                out_msg << done_tag;
        }
    }

    template <class Engine, class Tuple, size_t... Indexes>
    static inline auto make_client_socket(const Tuple& t, const std::index_sequence<Indexes...>&)
    {
        return ipc::client_socket<Engine>(std::get<Indexes>(t)...);
    }

    template <class Engine, class... Args>
    static inline auto make_client_socket(const std::tuple<Args...>& tuple)
    {
        return make_client_socket<Engine>(tuple, std::make_index_sequence<sizeof...(Args)>());
    }

    template <uint32_t Id, typename R, class Engine, typename Tuple, typename Dispatcher, typename Predicate, typename... Args>
    inline R service_invoker::call_by_address(const Tuple& address, Dispatcher& dispatcher, const Predicate& pred, const Args&... args)
    {
        auto client_socket = make_client_socket<Engine>(address);
        
        out_message request;
        request << (uint32_t)Id;
        if constexpr (sizeof...(args) != 0)
            (request << ... << args);

        in_message response;
        while (true)
        {
            client_socket.send_request(request, response, pred);
            
            uint32_t callback_id = 0;
            response >> callback_id;
    
            if (!dispatcher(callback_id, response, request))
            {
                if constexpr (!std::is_same_v<void, R>)
                {
                    R result{};
                    response >> result;
    
                    return result;
                }
                else
                    return;
            }
        }
    }
    
    template <uint32_t id, typename R, typename Predicate, class Engine, typename... Args>
    R service_invoker::call_by_channel(server_data_socket<Engine>& socket, in_message& in_msg, out_message& out_msg, const Predicate& pred, const Args&... args)
    {
        try
        {
            class message_cleaner
            {
                in_message& m_in_msg;
                out_message& m_out_msg;
            public:
                message_cleaner(in_message& in_msg, out_message& out_msg) noexcept : m_in_msg(in_msg), m_out_msg(out_msg) {}
                ~message_cleaner()
                {
                    m_in_msg.clear();
                    m_out_msg.clear();
                }
            } message_state_guard(in_msg, out_msg);

            out_msg.clear();
            out_msg << id;
            if constexpr (sizeof...(args) != 0)
                (out_msg << ... << args);
            socket.send_response(out_msg, pred);
    
            socket.get_request(in_msg, pred);
            if constexpr (std::is_same_v<void, R>)
                return;
            else
            {
                R result{};
                in_msg >> result;
                return result;
            }
        }
        catch (...)
        {
            socket.close();
            throw;
        }
    }
}

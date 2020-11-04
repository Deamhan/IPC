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
                auto p2p_socket = m_server_socket.accept(*predicate);
                p2p_socket.read_message(in_msg, *predicate);
    
                uint32_t function = 0;
                in_msg >> function;
                d->invoke(function, in_msg, out_msg, p2p_socket);
                p2p_socket.write_message(out_msg, *predicate);
                p2p_socket.wait_for_shutdown(*predicate);
            }
            catch (const std::exception& ex)
            {
                d->report_error(ex);
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

    template <size_t Tuple_size>
    struct client_channel_traits;

    template<>
    struct client_channel_traits<1>
    {
        typedef ipc::unix_client_socket type;
    };

    template<>
    struct client_channel_traits<2>
    {
        typedef ipc::tcp_client_socket type;
    };

    template <size_t Tuple_size>
    using client_channel_traits_t = client_channel_traits<Tuple_size>;

    template <typename Tuple>
    static inline auto make_client_socket(const Tuple& tuple)
    {
        static_assert(std::tuple_size_v<Tuple> == 1 || std::tuple_size_v<Tuple> == 2, "tuple must contain one parameter for UNIX socket and 2 parameters for TCP connection");

        if constexpr (std::tuple_size_v<Tuple> == 2)
            return ipc::tcp_client_socket(std::get<0>(tuple), std::get<1>(tuple));
        else
            return ipc::unix_client_socket(std::get<0>(tuple));
    }

    template <uint32_t Id, typename R, typename Tuple, typename Dispatcher, typename Predicate, typename... Args>
    inline R service_invoker::call_by_address(const Tuple& address, Dispatcher& dispatcher, const Predicate& pred, const Args&... args)
    {
        auto client_socket = make_client_socket(address);
        
        out_message request;
        request << (uint32_t)Id;
        if constexpr (sizeof...(args) != 0)
            (request << ... << args);

        in_message response;
        while (true)
        {
            client_socket.write_message(request, pred);
            
            uint32_t callback_id = 0;
            client_socket.read_message(response, pred);
            response >> callback_id;
            request.clear();
    
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
    
    template <uint32_t id, typename R, typename Predicate, typename... Args>
    R service_invoker::call_by_channel(point_to_point_socket& socket, in_message& in_msg, out_message& out_msg, const Predicate& pred, const Args&... args)
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
            socket.write_message(out_msg, pred);
    
            socket.read_message(in_msg, pred);
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

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

#include "../include/rpc.hpp"

namespace ipc
{
    template <typename dispatcher_t, typename predicate_t>
    inline void rpc_server::run(const dispatcher_t& dispatcher, const predicate_t& predicate)
    {
        std::vector<std::thread> workers(std::thread::hardware_concurrency());
        for (auto& worker : workers)
            worker = std::thread(&rpc_server::thread_proc<dispatcher_t, predicate_t>, this, &dispatcher, &predicate);
    
        for (auto& worker : workers)
            worker.join();
    }
    
    template <typename dispatcher_t, typename predicate_t>
    inline void rpc_server::thread_proc(const dispatcher_t* d, const predicate_t* predicate)
    {
        in_message<true> in_msg;
        out_message<true> out_msg;
    
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
    static void input_tuple(in_message<true>& msg, [[maybe_unused]] Tuple& t, std::index_sequence<I...>)
    {
        if constexpr (sizeof...(I) != 0)
            (msg >> ... >> std::get<I>(t));
    }
    
    template <bool use_done_tag, typename R, typename... Args> template <typename func_t>
    inline void function_invoker<R(Args...), use_done_tag>::operator()(in_message<true>& in_msg, out_message<true>& out_msg, func_t&& func)
    {
        std::tuple<std::remove_reference_t<std::remove_cv_t<Args>>...> args;
        input_tuple(in_msg, args, std::make_index_sequence<sizeof...(Args)>{});
        out_msg.clear();
        if constexpr (!std::is_same_v<R, void>)
        {
            R result = std::apply(std::forward<func_t>(func), std::move(args));
            if constexpr (use_done_tag)
                out_msg << done_tag;
            out_msg << result;
        }
        else
        {
            std::apply(std::forward<func_t>(func), std::move(args));
            if constexpr (use_done_tag)
                out_msg << done_tag;
        }
    }
    
    template <uint32_t id, typename R, typename dispatcher_t, typename predicate_t, typename... Args>
    inline R service_invoker::call_by_link(const char* link, dispatcher_t& dispatcher, const predicate_t& pred, const Args&... args)
    {
        ipc::unix_client_socket<true> client_socket(link);
    
        out_message<true> request;
        request << (uint32_t)id;
        if constexpr (sizeof...(args) != 0)
            (request << ... << args);

        in_message<true> response;
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
    
    template <uint32_t id, typename R, typename predicate_t, typename... Args>
    R service_invoker::call_by_channel(point_to_point_socket<true>& socket, in_message<true>& in_msg, out_message<true>& out_msg, const predicate_t& pred, const Args&... args)
    {
        try
        {
            class message_cleaner
            {
                in_message<true>& m_in_msg;
                out_message<true>& m_out_msg;
            public:
                message_cleaner(in_message<true>& in_msg, out_message<true>& out_msg) noexcept : m_in_msg(in_msg), m_out_msg(out_msg) {}
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

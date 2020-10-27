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

#include "../include/rpc.h"

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
    template <typename Dispatcher, typename pred>
    inline void rpc_server::run(const Dispatcher& dispatcher, const pred& predicate)
    {
        if (!m_ok)
            return;
    
        std::vector<std::thread> workers(std::thread::hardware_concurrency());
        for (auto& worker : workers)
            worker = std::thread(&rpc_server::thread_proc<Dispatcher, pred>, this, &dispatcher, &predicate);
    
        for (auto& worker : workers)
            worker.join();
    }
    
    template <typename Dispatcher, typename pred>
    inline void rpc_server::thread_proc(const Dispatcher* d, const pred* predicate)
    {
        std::string path;
        in_message in_msg;
        out_message out_msg;
    
        while ((*predicate)())
        {
            try
            {
                auto p2p_socket = m_server_socket.accept(*predicate);
                if (!p2p_socket.read_message(in_msg, *predicate))
                    throw channel_read_exception(__FUNCTION_NAME__);
    
                uint32_t function = d->get_default();
                in_msg >> function;
                if (in_msg.is_ok())
                {
                    d->invoke(function, in_msg, out_msg, p2p_socket);
    
                    if (!p2p_socket.write_message(out_msg, *predicate))
                        throw channel_write_exception(__FUNCTION_NAME__);
                    p2p_socket.wait_for_shutdown(*predicate);
                }
            }
            catch (const bad_channel_exception& ex)
            {
                d->report_error(ex);
            }
            catch (const message_format_exception& ex)
            {
                d->report_error(ex);
            }
            catch (const message_overflow_exception& ex)
            {
                d->report_error(ex);
            }
            catch (const channel_read_exception& ex)
            {
                d->report_error(ex);
            }
            catch (const channel_write_exception& ex)
            {
                d->report_error(ex);
            }
        }
    }
    
    template <typename Tuple, size_t... I>
    static bool input_tuple(in_message& msg, [[maybe_unused]] Tuple& t, std::index_sequence<I...>)
    {
        if constexpr (sizeof...(I) != 0)
            (msg >> ... >> std::get<I>(t));
    
        return msg.is_ok();
    }
    
    template <bool use_done_tag, typename R, typename... Args> template <typename Func>
    inline void function_invoker<R(Args...), use_done_tag>::operator()(in_message& in_msg, out_message& out_msg, Func&& func)
    {
        std::tuple<std::remove_reference_t<std::remove_cv_t<Args>>...> args;
        if (input_tuple(in_msg, args, std::make_index_sequence<sizeof...(Args)>{}))
        {
            out_msg.clear();
            if constexpr (!std::is_same_v<R, void>)
            {
                R result = std::apply(std::forward<Func>(func), std::move(args));
                if constexpr (use_done_tag)
                    out_msg << done_tag;
                out_msg << result;
            }
            else
            {
                std::apply(std::forward<Func>(func), std::move(args));
                if constexpr (use_done_tag)
                    out_msg << done_tag;
            }
    
            if (!out_msg.is_ok())
                throw message_overflow_exception(__FUNCTION_NAME__);
        }
        else
            throw message_format_exception(__FUNCTION_NAME__);
    }
    
    template <uint32_t id, typename R, typename Dispatcher, typename Predicate, typename... Args>
    inline R service_invoker::call_by_link(const char* link, Dispatcher&& dispatcher, const Predicate& pred, const Args&... args)
    {
        ipc::unix_client_socket client_socket(link);
        if (!client_socket.is_ok())
            throw ipc::bad_channel_exception(__FUNCTION_NAME__);
    
        ipc::out_message request;
        request << (uint32_t)id;
        if constexpr (sizeof...(args) != 0)
            (request << ... << args);
    
        if (!request.is_ok())
            throw ipc::message_overflow_exception(__FUNCTION_NAME__);
    
        if (!client_socket.write_message(request, pred))
            throw ipc::channel_write_exception(__FUNCTION_NAME__);
    
        ipc::in_message response;
        while (true)
        {
            uint32_t callback_id = 0;
            if (!client_socket.read_message(response, pred))
                throw ipc::channel_read_exception(__FUNCTION_NAME__);
    
            request.clear();
            if (!(response >> callback_id).is_ok())
                throw ipc::message_format_exception(__FUNCTION_NAME__);
    
            if (!dispatcher(callback_id, response, request))
            {
                if constexpr (!std::is_same_v<void, R>)
                {
                    R result{};
                    response >> result;
                    client_socket.shutdown();
                    if (!request.is_ok())
                        throw ipc::message_format_exception(__FUNCTION_NAME__);
    
                    return result;
                }
                else
                {
                    client_socket.shutdown();
                    return;
                }
    
            }
    
            if (!client_socket.write_message(request, pred))
                throw ipc::channel_write_exception(__FUNCTION_NAME__);
        }
    }
    
    template <uint32_t id, typename R, typename Predicate, typename... Args>
    R service_invoker::call_by_channel(point_to_point_socket& socket, in_message& in_msg, out_message& out_msg, const Predicate& pred, const Args&... args)
    {
        try
        {
            if (socket.is_ok())
            {
                out_msg.clear();
                out_msg << id;
                if constexpr (sizeof...(args) != 0) //gcc 'statement has no effect' workaround
                    (out_msg << ... << args);
    
                if (!out_msg.is_ok())
                    throw message_overflow_exception(__FUNCTION_NAME__);
                if (!socket.write_message(out_msg, pred))
                    throw channel_write_exception(__FUNCTION_NAME__);
            }
            else
                throw bad_channel_exception(__FUNCTION_NAME__);
    
            if (socket.read_message(in_msg, pred))
            {
                if constexpr (std::is_same_v<void, R>)
                    return;
                else
                {
                    R result{};
                    if ((in_msg >> result).is_ok())
                        return result;
                    else
                        throw message_format_exception(__FUNCTION_NAME__);
                }
            }
            else
                throw channel_read_exception(__FUNCTION_NAME__);
        }
        catch (...)
        {
            socket.close();
            throw;
        }
    }
}

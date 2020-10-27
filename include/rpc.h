/**
 * Lightweight inter process communication library
 * Copyright (C) 2020 Pavel Kovalenko 
 *
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include  <thread>

#include "ipc.h"

namespace ipc
{
    class function_invoker_base
    {
    public:
        static const uint32_t done_tag = 0xFFFFFFFF;
    protected:
        function_invoker_base() = default;
    };

    template <typename, bool>
    class function_invoker;

    template <bool use_done_tag, typename R, typename... Args>
    class function_invoker<R(Args...), use_done_tag> : public function_invoker_base
    {
    public:
        template <typename Func>
        void operator()(in_message& in_msg, out_message& out_msg, Func&& func);
    };

    class service_invoker
    {
    public:
        template <uint32_t id, typename R, typename Dispatcher, typename Predicate, typename... Args>
        R call_by_link(const char * link, Dispatcher&& dispatcher, const Predicate& pred, const Args&... args);

        template <uint32_t id, typename R, typename Predicate, typename... Args>
        R call_by_channel(point_to_point_socket& socket, in_message& in_msg, out_message& out_msg, const Predicate& pred, const Args&... args);
    };

    class rpc_server
    {
    public:
        rpc_server(std::string_view path) : m_server_socket(std::string(path)), m_ok(m_server_socket.is_ok()) {}

        template <typename Dispatcher, typename pred>
        void run(const Dispatcher& dispatcher, const pred& predicate);

        bool is_ok() const noexcept { return m_ok; }

    protected:
        unix_server_socket m_server_socket;
        bool m_ok;

        template <typename Dispatcher, typename pred>
        void thread_proc(const Dispatcher* d, const pred* predicate);
    };
}

#include "../source/rpc_impl.h"

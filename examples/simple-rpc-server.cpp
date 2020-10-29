#include <atomic>
#include <clocale>
#include <iostream>

#include <signal.h>

#include "../include/rpc.hpp"

#include "simple-rpc-common.hpp"

static void clearSignalHandlers() noexcept
{
    signal(SIGINT, SIG_IGN);
#ifdef _WIN32
    signal(SIGBREAK, SIG_IGN);
    signal(CTRL_CLOSE_EVENT, SIG_IGN);
    signal(CTRL_LOGOFF_EVENT, SIG_IGN);
    signal(CTRL_SHUTDOWN_EVENT, SIG_IGN);
#endif
    signal(SIGTERM, SIG_IGN);
}

static void installSignalHandlers(void(*handler)(int)) noexcept
{
    signal(SIGINT, handler);
#ifdef _WIN32
    signal(SIGBREAK, handler);
    signal(CTRL_CLOSE_EVENT, handler);
    signal(CTRL_LOGOFF_EVENT, handler);
    signal(CTRL_SHUTDOWN_EVENT, handler);
#endif
    signal(SIGTERM, handler);
}

static std::atomic<bool> g_stop = false;

static void ctrlBreakHandler(int /*signum*/) noexcept
{
    clearSignalHandlers();
    g_stop = true;
}

auto predicate = []() { return !g_stop; };

class dispatcher
{
public:
    void invoke(uint32_t id, ipc::in_message<true>& in_msg, ipc::out_message<true>& out_msg, ipc::point_to_point_socket<true>& p2p_socket) const
    {
        switch ((simple_server_function_t)id)
        {
        case simple_server_function_t::add_with_callbacks:
            ipc::function_invoker<int32_t(ipc::message::remote_ptr), true>()(in_msg, out_msg, [&p2p_socket, &in_msg, &out_msg](const ipc::message::remote_ptr& p) mutable -> int32_t {
                int32_t arg1 = ipc::service_invoker().call_by_channel<(uint32_t)simple_client_function_t::arg1, int32_t>(p2p_socket, in_msg, out_msg, predicate, p);
                int32_t arg2 = ipc::service_invoker().call_by_channel<(uint32_t)simple_client_function_t::arg2, int32_t>(p2p_socket, in_msg, out_msg, predicate, p);

                return arg1 + arg2;
                });
            break;
        case simple_server_function_t::add:
            ipc::function_invoker<int32_t(int32_t, int32_t), true>()(in_msg, out_msg, [](int32_t arg1, int32_t arg2) -> int32_t { return arg1 + arg2; });
            break;
        default:
            break;
        }
    }

    void report_error(const std::exception& ex) const noexcept
    {
        if (!g_stop)
            std::cout << "call error >> " << ex.what() << std::endl;
    }
};

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");
        installSignalHandlers(ctrlBreakHandler);

        const char * link = "foo";
        ipc::rpc_server server(link);
        server.run(dispatcher(), predicate);
    }
    catch(const std::exception& ex) 
    {
        if (!g_stop)
        {
            std::cout << "fatal error >> " << ex.what() <<std::endl;
            return 1;
        }
    } 

    std::cout << "good bye" << std::endl;
    return 0;
}
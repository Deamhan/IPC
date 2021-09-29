#include <clocale>
#include <iostream>

#include "../include/rpc.hpp"

#include "simple-rpc-common.hpp"

static void clear_signal_handlers() noexcept
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

static void install_signal_handlers(void(*handler)(int)) noexcept
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

static void signal_handler(int /*signum*/) noexcept
{
    clear_signal_handlers();
    g_stop = true;
}

auto predicate = []() { return !g_stop; };

struct add_args
{
    int32_t a;
    int32_t b;
};

static bool dispatch(uint32_t id, ipc::in_message& in_msg, ipc::out_message& out_msg)
{
    switch ((simple_client_function_t)id)
    {
    case simple_client_function_t::arg1:
        ipc::function_invoker<int32_t(ipc::message::remote_ptr<true>), false>()(in_msg, out_msg, [](const ipc::message::remote_ptr<true>& p) {
            return ((const add_args*)p.get_pointer())->a; 
        });
        return true;
    case simple_client_function_t::arg2:
        ipc::function_invoker<int32_t(ipc::message::remote_ptr<true>), false>()(in_msg, out_msg, [](const ipc::message::remote_ptr<true>& p) {
            return ((const add_args*)p.get_pointer())->b; 
        });
        return true;
    default:
        return false;
    }
}

static bool minimal_dispatch(uint32_t id, ipc::in_message& in_msg, ipc::out_message& out_msg)
{
    return false;
}

int main()
{
    std::setlocale(LC_ALL, "");
    install_signal_handlers(signal_handler);
    
    try
    {
        add_args args = { 3, 4 };
        auto result = ipc::service_invoker().call_by_address<(uint32_t)simple_server_function_t::add_with_callbacks, int32_t, client_engine_t>(
            std::tuple{ ADDRESS_ARGS }, dispatch, predicate, ipc::message::remote_ptr<true>(&args));
        std::cout << "add(" << args.a << ", " << args.b << ") = " << result << std::endl;

        int32_t a = 7, b = 8;
        result = ipc::service_invoker().call_by_address<(uint32_t)simple_server_function_t::add, int32_t, client_engine_t>(
            std::tuple{ ADDRESS_ARGS }, minimal_dispatch, predicate, a, b);
        std::cout << "add(" << a << ", " << b << ") = " << result << std::endl;

        return 0;
    }
    catch (const ipc::user_stop_request_exception&)
    {
        std::cout << "stop signal was received" << std::endl;
    }
    catch (const std::exception& ex)
    {
        std::cout << "error >> " << ex.what() << std::endl;
        return 1;
    }
    
    return 0;
}

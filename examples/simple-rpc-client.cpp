#include <clocale>
#include <iostream>

#include "../include/rpc.hpp"

#include "simple-rpc-common.hpp"

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
        ipc::function_invoker<int32_t(ipc::message::remote_ptr<true>), false>()(in_msg, out_msg, [](const ipc::message::remote_ptr<true>& p) { return ((const add_args*)p.get_pointer())->a; });
        return true;
    case simple_client_function_t::arg2:
        ipc::function_invoker<int32_t(ipc::message::remote_ptr<true>), false>()(in_msg, out_msg, [](const ipc::message::remote_ptr<true>& p) { return ((const add_args*)p.get_pointer())->b; });
        return true;
    default:
        return false;
    }
}

static bool minimal_dispatch(uint32_t id, ipc::in_message& in_msg, ipc::out_message& out_msg)
{
    return false;
}

static auto minimal_predicate = []() { return true; };

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");

        add_args args = { 3, 4 };
        auto result = ipc::service_invoker().call_by_address<(uint32_t)simple_server_function_t::add_with_callbacks, int32_t, client_engine_t>(std::tuple{ ADDRESS_ARGS }, dispatch, minimal_predicate, ipc::message::remote_ptr<true>(&args));
        std::cout << "add(" << args.a << ", " << args.b << ") = " << result << std::endl;

        int32_t a = 7, b = 8;
        result = ipc::service_invoker().call_by_address<(uint32_t)simple_server_function_t::add, int32_t, client_engine_t>(std::tuple{ ADDRESS_ARGS }, minimal_dispatch, minimal_predicate, a, b);
        std::cout << "add(" << a << ", " << b << ") = " << result << std::endl;

        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cout << "error >> " << ex.what() << std::endl;
        return 1;
    }
}
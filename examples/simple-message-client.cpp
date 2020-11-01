#include <clocale>
#include <iostream>

#include "../include/ipc.hpp"
#include "simple-rpc-common.hpp"

static const char* link = "foo";

struct add_args
{
    int32_t a;
    int32_t b;
};

int32_t call_add_with_callbacks(add_args * args)
{
    ipc::unix_client_socket client_socket(link);

    ipc::out_message out;
    out << (uint32_t)simple_server_function_t::add_with_callbacks << ipc::message::remote_ptr(args);

    auto predicate = []() { return true; };
    client_socket.write_message(out, predicate);

    ipc::in_message in;

    bool done = false;

    do
    {
        out.clear();
        uint32_t code;
        client_socket.read_message(in, predicate);
        in >> code;
        switch ((simple_client_function_t)code)
        {
        case simple_client_function_t::arg1:
        {
            ipc::message::remote_ptr p;
            in >> p;
            out << ((add_args*)p.get_pointer())->a;
            break;
        }
        case simple_client_function_t::arg2:
        {
            ipc::message::remote_ptr p;
            in >> p;
            out << ((add_args*)p.get_pointer())->b;
            break;
        }
        default:
            done = true;
            break;
        }

        if (done)
            break;

        client_socket.write_message(out, predicate);
    } while (true);

    int32_t result = 0;
    in >> result;

    return result;
}

int32_t call_add(int32_t a, int32_t b)
{
    ipc::unix_client_socket client_socket(link);

    ipc::out_message out;
    out << (uint32_t)simple_server_function_t::add << a << b;

    auto predicate = []() { return true; };
    client_socket.write_message(out, predicate);

    ipc::in_message in;
    client_socket.read_message(in, predicate);

    uint32_t code = 0;
    int32_t result = 0;
    in >> code >> result;

    return result;
}

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");

        add_args args = { 3, 4 };
        int32_t a = 7, b = 8;

        std::cout << "add(" << args.a << ", " << args.b << ") = " << call_add_with_callbacks(&args) << std::endl;
        std::cout << "add(" << a << ", " << b << ") = " << call_add(a, b) << std::endl;
    
        return 0;
    }
    catch(const std::exception& ex) 
    {
        std::cout << "error >> " << ex.what() << std::endl;
        return 1;
    }         
}

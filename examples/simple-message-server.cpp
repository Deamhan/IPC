#include <atomic>
#include <clocale>
#include <iostream>
#include <thread>
#include <vector>

#include <signal.h>

#include "../include/ipc.hpp"
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

static void process_request(ipc::tcp_server_socket* server_socket)
{
    try
    {
        while (!g_stop)
        {
            auto predicate = []() { return !g_stop; };
            auto connection_socket = server_socket->accept(predicate);

            try
            {
                ipc::in_message in;
                ipc::out_message out;
                connection_socket.get_request(in, predicate);

                uint32_t code;
                in >> code;
                switch ((simple_server_function_t)code)
                {
                case simple_server_function_t::add_with_callbacks:
                {
                    ipc::message::remote_ptr<true> p;
                    in >> p;
                    int32_t args[2] = {};
                    uint32_t codes[2] = { (uint32_t)simple_client_function_t::arg1, (uint32_t)simple_client_function_t::arg2 };
                    for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); ++i)
                    {
                        out.clear();
                        out << codes[i] << p;
                        connection_socket.send_response(out, predicate);
                        connection_socket.get_request(in, predicate);
                        in >> args[i];
                    }

                    out.clear();
                    out << uint32_t(0xFFFFFFFFu) << (args[1] + args[0]);
                    break;
                }
                case simple_server_function_t::add:
                {
                    int32_t a = 0, b = 0;
                    in >> a >> b;
                    out << uint32_t(0xFFFFFFFFu) << (a + b);
                    break;
                }
                default:
                    break;
                }

                connection_socket.send_response(out, predicate);
                connection_socket.wait_for_shutdown(predicate);
            }
            catch (const std::exception& ex)
            {
                std::cout << "request error >> " << ex.what() << std::endl;
            }
        }
    }
    catch (const ipc::user_stop_request_exception&) {}
    catch (const std::exception& ex)
    {
        std::cout << "fatal error >> " << ex.what() << std::endl;
    }
}

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");
        install_signal_handlers(signal_handler);

        ipc::tcp_server_socket server_socket(port);
        
        std::cout << "server is ready" << std::endl;

        std::vector<std::thread> pool(std::thread::hardware_concurrency());
        for (auto& t : pool)
            t = std::thread(process_request, &server_socket);
        for (auto& t : pool)
            t.join();
    }
    catch(const std::exception& ex) 
    {
        if (!g_stop)
        {
            std::cout << "fatal error >> " << ex.what() << std::endl;
            return 1;
        }
    } 

    std::cout << "good bye" << std::endl;
    return 0;
}

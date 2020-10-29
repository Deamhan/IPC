#include <atomic>
#include <clocale>
#include <iostream>
#include <thread>
#include <vector>

#include <signal.h>

#include "../include/ipc.hpp"
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

static void process_request(ipc::unix_server_socket<true> * server_socket)
{
    while (!g_stop)
    {
        auto predicate = []() { return !g_stop; };
        auto p2p = server_socket->accept(predicate);

        try
        {
            ipc::in_message<true> in;
            ipc::out_message<true> out;
            p2p.read_message(in, predicate);

            uint32_t code;
            in >> code;
            switch ((simple_server_function_t)code)
            {
            case simple_server_function_t::add_with_callbacks:
            {
                ipc::message::remote_ptr p;
                in >> p;
                int32_t args[2] = {};
                uint32_t codes[2] = { (uint32_t)simple_client_function_t::arg1, (uint32_t)simple_client_function_t::arg2 };
                for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); ++i)
                {
                    out.clear();
                    out << codes[i] << p;
                    p2p.write_message(out, predicate);
                    p2p.read_message(in, predicate);
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

            p2p.write_message(out, predicate);
            p2p.wait_for_shutdown(predicate);
        }
        catch (const std::exception& ex)
        {
            std::cout << "request error >> " << ex.what() << std::endl;
        }
    }
}

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");
        installSignalHandlers(ctrlBreakHandler);

        const char * link = "foo";
        ipc::unix_server_socket<true> server_socket(std::string{ link });
        
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
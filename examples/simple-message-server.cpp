#include <atomic>
#include <clocale>
#include <iostream>

#include <signal.h>

#include "../include/ipc.hpp"

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

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");
        installSignalHandlers(ctrlBreakHandler);

        const char * link = "foo";
        ipc::unix_server_socket<true> server_socket(std::string{ link });
        
        std::cout << "server is ready" << std::endl;

        while (!g_stop)
        {
            auto predicate = []() { return !g_stop; };
            auto p2p = server_socket.accept(predicate);
        
            try
            {
                ipc::in_message<true> in;
                p2p.read_message(in, predicate);
        
                std::string req;
                in >> req;
        
                ipc::out_message<true> out;
                out << req + " processed";
                p2p.write_message(out, predicate);
        
                p2p.wait_for_shutdown(predicate);   
            }
            catch(const std::exception& ex)
            {
                std::cout << "request error >> " << ex.what() << std::endl;
            }
        }
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
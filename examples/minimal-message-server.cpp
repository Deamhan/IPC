#include <atomic>
#include <clocale>
#include <iostream>
#include <thread>
#include <vector>

#include <signal.h>

#include "../include/ipc.hpp"

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

static const int port = 12345;

int main()
{
    install_signal_handlers(signal_handler);

    try
    {
        ipc::tcp_server_socket server_socket(port); // has already been described
        
        auto predicate = []() { return !g_stop; };
        while (!g_stop)
        {
            auto connection_socket = server_socket.accept(predicate);
            
            try
            {
                ipc::in_message in;
                connection_socket.get_request(in, predicate);
                
                std::string req;
                in >> req;
                
                ipc::out_message out;
                out << req + " processed";
                
                connection_socket.send_response(out, predicate);           
                connection_socket.wait_for_shutdown(predicate);   
            }
            catch (const ipc::user_stop_request_exception&) { throw; }
            catch (std::exception& ex)
            {
                std::cout << "request error >> " << ex.what() << std::endl;
            }
        }
    }
    catch (const ipc::user_stop_request_exception&) 
    {
        std::cout << "stop signal was received" << std::endl;
    }
    catch (const std::exception& ex)
    {
        std::cout << "fatal error >> " << ex.what() << std::endl;
        return 1;
    }

    std::cout << "good bye" << std::endl;
    return 0;
}

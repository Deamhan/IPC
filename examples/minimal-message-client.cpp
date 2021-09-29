#include <clocale>
#include <iostream>

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

static const char* host = "localhost";
static const int port = 12345;

int main()
{
    install_signal_handlers(signal_handler);

    try
    {
        ipc::tcp_client_socket client_socket(host, port);
        ipc::out_message out;
        const char * req_text = "request";
        out << req_text;
        
        ipc::in_message in;
        auto predicate = []() { return !g_stop; };
        client_socket.send_request(out, in, predicate);
        
        std::string resp;
        in >> resp;
        
        std::cout << req_text << " -> " << resp << std::endl;
    }
    catch (const ipc::user_stop_request_exception&)
    {
        std::cout << "stop signal was received" << std::endl;
    }
    catch(const std::exception& ex) 
    {
        std::cout << "error >> " << ex.what() << std::endl;
        return 1;
    }        
    
    return 0;
}

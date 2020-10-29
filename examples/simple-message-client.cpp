#include <clocale>

#include "../include/ipc.hpp"

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");

        const char * link = "foo";
        ipc::unix_client_socket<true> client_socket(link);
    
        ipc::out_message<true> out;
        const char * req_text = "request";
        out << req_text;
    
        auto predicate = []() { return true; };
        client_socket.write_message(out, predicate);
    
        ipc::in_message<true> in;
        client_socket.read_message(in, predicate);
    
        std::string resp;
        in >> resp;
    
        printf("%s -> %s\n", req_text, resp.c_str());
    
        client_socket.shutdown(); 
        return 0;
    }
    catch(const std::exception& ex) 
    {
        printf("error: %s\n", ex.what());
        return 1;
    }         
}
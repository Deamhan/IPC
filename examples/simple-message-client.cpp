#include <clocale>
#include <iostream>

#include "../include/ipc.hpp"

int main()
{
    try
    {
        std::setlocale(LC_ALL, "");

        const char * link = "foo";
        ipc::unix_client_socket client_socket(link);
    
        ipc::out_message out;
        const char * req_text = "request";
        out << req_text;
    
        auto predicate = []() { return true; };
        client_socket.write_message(out, predicate);
    
        ipc::in_message in;
        client_socket.read_message(in, predicate);
    
        std::string resp;
        in >> resp;
    
        std::cout << req_text << " -> " << resp;
    
        return 0;
    }
    catch(const std::exception& ex) 
    {
        std::cout << "error >> " << ex.what() << std::endl;
        return 1;
    }         
}

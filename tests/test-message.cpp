#include <algorithm>

#include "ipc.hpp"

int main()
{
    std::string s1("Test"), s2;
    int32_t i1 = 123, i2 = 0;
    char c1 = 'T', c2 = '\0';
    
    ipc::out_message<false> out;
    out << s1 << c1 << i1;
    
    ipc::in_message<false> in;
    const auto& out_data = out.get_data();
    std::copy(out_data.begin(), out_data.end(), in.get_data().begin());
    
    in >> s2 >> c2 >> i2;
    
    return (s1 == s2 && c1 == c2 && i1 == i2) ? 0 : 1;
}
enum class simple_server_function_t
{
	add_with_callbacks = 0,
	add,

	unknown
};

enum class simple_client_function_t
{
	arg1 = 0,
	arg2
};

#define USE_ALPC 1

#if defined(__HYPER_V__)
#   if defined (_WIN32)
	const wchar_t* vm_id = L"{00000000-0000-0000-0000-000000000000}";      // Hyper-V is a server
	const wchar_t* service_id = L"{00003039-facb-11e6-bd58-64006a7986d3}"; // must be registered here: "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices"
#   elif defined(__linux__)
    unsigned vm_id = 2;          // hypervisor is a server
    unsigned service_id = 12345; // keep in sync with service_id GUID
#   endif
	#define port vm_id, service_id
	typedef ipc::hyperv_server_socket_engine server_engine_t;
	typedef ipc::hyperv_client_socket_engine client_engine_t;
#	define ADDRESS_ARGS port
#elif defined(_WIN32) && defined(USE_ALPC)
	static const wchar_t* port = L"\\RPC Control\\test_ipc_port";
	typedef ipc::alpc_server_engine server_engine_t;
	typedef ipc::alpc_client_engine client_engine_t;
#	define ADDRESS_ARGS port
#elif defined(__AFUNIX_H__) && defined(USE_UNIX_SOCKET)
	static const char* port = "test_ipc_port";
	typedef ipc::unix_server_socket_engine server_engine_t;
	typedef ipc::unix_client_socket_engine client_engine_t;
#	define ADDRESS_ARGS port
#else
	static uint16_t port = 12345;
	typedef ipc::tcp_server_socket_engine server_engine_t;
	typedef ipc::tcp_client_socket_engine client_engine_t;
#	ifndef SERVER_ADDRESS
#		define SERVER_ADDRESS "localhost"
#	endif
#	define ADDRESS_ARGS SERVER_ADDRESS, port
#endif

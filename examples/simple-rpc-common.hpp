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
	const wchar_t* vm_id = L"{e0e16197-dd56-4a10-9195-5ee7a155a838}";
	const wchar_t* service_id = L"{9b5307be-f1b5-4687-9e6d-b2ea6d52c562}";
#   elif defined(__linux__)
    unsigned vm_id = 2;
    unsigned service_id = 12345;
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

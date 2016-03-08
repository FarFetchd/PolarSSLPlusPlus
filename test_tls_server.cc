#include <iostream>

using std::cout;
using std::cerr;
using std::endl;

#include "polar_tls_server.h"

int main()
{
	int listen_socket, ret;
	if((ret = net_bind(&listen_socket, "127.0.0.1", 7777)) != 0)
	{
		cerr << "bind() and listen() failure." << endl;
		return 1;
	}
	int accepted_socket;
	net_accept(listen_socket, &accepted_socket, NULL);
	
	PolarTLSServer server;
	
	if(!(server.loadCert("the_servers_cert.crt") && server.loadKey("the_servers_key.key")))
	{
		cerr << "The server's cert or key file is missing." << endl;
		return 1;
	}
	
	server.acceptTLS(accepted_socket);
	
	unsigned char client_says[100]; memset(client_says, 0, 100);
	std::string server_says("Hello to you too!");
	server.recvTLS(client_says, 99); client_says[99]=0;
	server.sendTLS((const unsigned char*)server_says.c_str(), server_says.length());
	
	//NOTE: could explicitly call server.shutdownTLS() here, but it's ok not to;
	//		the dtor will call it for us.
	
	cout << client_says << endl;
}

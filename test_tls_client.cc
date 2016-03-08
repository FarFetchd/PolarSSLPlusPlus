#include <iostream>

using std::cout;
using std::endl;

#include "polar_tls_client.h"


void clientToGoogle()
{
	cout << "=================CLIENT TO GOOGLE================" << endl;
	
	PolarTLSClient client;
	
	client.setRootCerts("/usr/share/ca-certificates/mozilla");
	client.connectTLS("google.com", 443);
	std::string get_google("GET / HTTP/1.0\r\n\r\n");
	client.sendTLS((const unsigned char*)get_google.c_str(), get_google.length());
	unsigned char buf[100]; memset(buf, 0, 100);
	client.recvTLS(buf, 99); buf[99] = 0;
	cout << buf << endl;
	
	//NOTE: could also just let it go out of scope; dtor would call shutdown.
	client.shutdownTLS();
	cout << "===============END CLIENT TO GOOGLE==============\n\n" << endl;
}

void clientToGoogleDelayedHandshake()
{
	cout << "=================CLIENT TO GOOGLE2===============" << endl;
	
	int tcp_socket;
	net_connect(&tcp_socket, "google.com", 443);
	
	
	//NOTE: handshakeTLS() is useful in the case where some communication 
	//happens in between the TCP connection being established, and the two 
	//sides wanting to establish TLS. This pointless use of it is just a demo!
	
	
	PolarTLSClient client;
	client.setRootCerts("/usr/share/ca-certificates/mozilla");
	
	client.setServerCNAME("www.google.com");
	client.handshakeTLS(tcp_socket);
	
	
	
	std::string get_google("GET / HTTP/1.0\r\n\r\n");
	client.sendTLS((const unsigned char*)get_google.c_str(), get_google.length());
	unsigned char buf[100]; memset(buf, 0, 100);
	client.recvTLS(buf, 99); buf[99] = 0;
	cout << buf << endl;
	
	//NOTE: could also just let it go out of scope; dtor would call shutdown.
	client.shutdownTLS();
	cout << "===============END CLIENT TO GOOGLE2=============\n\n" << endl;
	
}

void clientToSelf()
{
	cout << "==================CLIENT TO SELF=================" << endl;
	
	PolarTLSClient client;
	
	client.setServerCert("the_servers_cert.crt");
	client.connectTLS("127.0.0.1", 7777);
	std::string say_hello("Hello there!");
	client.sendTLS((const unsigned char*)say_hello.c_str(), say_hello.length());
	unsigned char buf[100]; memset(buf, 0, 100);
	client.recvTLS(buf, 99); buf[99] = 0;
	cout << buf << endl;
	
	//NOTE: could also just let it go out of scope; dtor would call shutdown.
	client.shutdownTLS();
	cout << "================END CLIENT TO SELF===============\n\n\n" << endl;
}

int main()
{
	clientToGoogle();
	clientToGoogleDelayedHandshake();
	
	//be sure test_tls_server is already running!
	clientToSelf();
}
 

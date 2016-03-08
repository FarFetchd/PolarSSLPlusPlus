#ifndef _INCLGUARD_POLARPLUSPLUS_TLS_CLIENT_H_
#define _INCLGUARD_POLARPLUSPLUS_TLS_CLIENT_H_

#include "polar_tls_session.h"


class PolarTLSClient : public PolarTLSSession
{
public:
	//Usage: call (exactly) one of setServerCert() or setRootCerts(), and then
	//connectTLS(). All will return true if everything is working correctly.
	
	//This session will only go forward if the server has the private key 
	//associated with this cert's public key. (CNAME not checked).
	bool setServerCert(std::string partner_cert_file_path);
	
	//This session will be willing to connect to any server with a valid cert 
	//chain that goes back to a trusted root cert.
	//NOTE: on ubuntu (and maybe others?), root_certs_directory should be:
	//			"/usr/share/ca-certificates/mozilla"
	bool setRootCerts(std::string root_certs_directory);
	
	//Establishes a TCP connection to the given hostname and port, and then
	//establishes a TLS session with that server (expecting the server cert, 
	//or a cert signed by a root cert, loaded earlier).
	bool connectTLS(std::string hostname, int port);
	
	
	
	
	
	
	//For establishing TLS on an existing TCP connection:
	//===================================================
	
	//Set what name we expect in the server's cert (e.g. "www.google.com").
	//NOTE: you only need to call this if you are using both setRootCerts()
	//AND handshakeTLS(). (CNAME is unused with setServerCert(), and 
	//connectTLS() will set it to the hostname if it has not been set).
	void setServerCNAME(std::string cname);
	
	//Establishes a TLS session on an existing TCP connection. NOTE: If it 
	//fails to establish a TLS session (even if just because the TLSClient 
	//object wasn't fully initialized), it will close the TCP connection.
	bool handshakeTLS(int connected_socket);
	

	
	
	PolarTLSClient();
	~PolarTLSClient();
private:
	bool using_root_certs;
	std::string expected_cname;
	
	x509_crt root_certs;
	x509_crt partner_cert;
};

#endif //_INCLGUARD_POLARPLUSPLUS_TLS_CLIENT_H_

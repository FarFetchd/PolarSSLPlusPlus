#ifndef _INCLGUARD_POLARPLUSPLUS_TLS_SERVER_H_
#define _INCLGUARD_POLARPLUSPLUS_TLS_SERVER_H_

#include <string>

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif


#include "polarssl/ssl.h"
#include "polarssl/certs.h"
#include "polarssl/pk.h"
#include "polar_tls_session.h"


class PolarTLSServer : public PolarTLSSession
{
public:
	
	//Must call both loadCert() and loadKey() before acceptTLS().
	bool loadCert(std::string cert_file_path);
	bool loadKey(std::string key_file_path);
	
	//client_socket should be a connected TCP socket, accepted by accept()
	//(or by PolarSSL's net_accept() or something like that). If this function
	//returns true, then you have a working TLS session, and you can call 
	//sendTLS(), recvTLS(), and shutdownTLS() on it! Hooray!
	bool acceptTLS(int client_socket);
	
	
	
	
	
	PolarTLSServer();
	~PolarTLSServer();
private:
	x509_crt our_cert;
	pk_context our_private_key;
	
	bool crtfile_loaded;
	bool keyfile_loaded;
};

#endif //_INCLGUARD_POLARPLUSPLUS_TLS_SERVER_H_

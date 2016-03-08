#ifndef _INCLGUARD_POLARPLUSPLUS_TLS_SESSION_H_
#define _INCLGUARD_POLARPLUSPLUS_TLS_SESSION_H_

#include <string>

#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

class PolarTLSSession
{
public:
	//Both the client and server subclasses can use these as if they were the
	//send() and recv() functions of TCP sockets. They return number of bytes
	//send/received, recv() returns 0 if the other side closed gracefully.
	//recv() blocks if nothing to receive yet, send() blocks if buffer full.
	int sendTLS(const unsigned char* buf, unsigned int len);
	int recvTLS(unsigned char* buf, unsigned int len);
	
	//Like close() for TCP sockets.
	void shutdownTLS();
	
	//TODO might want to add some sort of istream/ostream interface...
	//TODO sounds hard though!
	
	//If you never call this, errors will just be logged to stderr.
	void setLogFile(std::string _log_file);
	
	
	
	
	
	
	
	
	
	
	
protected:
	ssl_context ssl;
	int tcp_socket;
	bool initialized;
	bool certificate_loaded;
	bool connected;
	
	entropy_context polar_tls_entropy;
	ctr_drbg_context polar_tls_ctr_drbg;
	
	void logErrorFromPolarSSLCode(std::string extra_comment, int code);
	void logError(std::string the_message);
	
	bool init();
	PolarTLSSession();
	~PolarTLSSession();	
private:
	//------------------------------------------------------------------
	//ctr_drbg_free(&ctr_drbg)... not in the standard ubuntu package
	static void custom_polarssl_zeroize( void *v, size_t n );
	static void custom_aes_free( aes_context *ctx );
	static void custom_ctr_drbg_free( ctr_drbg_context *ctx );
	//------------------------------------------------------------------
	
	std::string log_file;
};

#endif //_INCLGUARD_POLARPLUSPLUS_TLS_SESSION_H_

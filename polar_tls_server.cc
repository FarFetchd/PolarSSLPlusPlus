#include <unistd.h>

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "polarssl/ctr_drbg.h"

#ifndef POLARSSL_CERTS_C
#error PolarSSL doesnt have certificate support compiled in!!! We need that!
#endif

#include "polar_tls_server.h"


bool PolarTLSServer::loadCert(std::string cert_file_path)
{
	if(!init())
		logError("loadCert() could not begin: init() failed.");
	
	int ret;	
	if(access(cert_file_path.c_str(), R_OK) == 0)
		ret = x509_crt_parse_file(&our_cert, cert_file_path.c_str());
	else
	{
		logError("The certificate file is corrupted or missing from "+cert_file_path+"!\n");
		return false;
	}
	if(ret < 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to parse the certificate: x509_crt_parse returned:", ret);
		return false;
	}
	
	crtfile_loaded = true;
	if(crtfile_loaded && keyfile_loaded)
		certificate_loaded = true;
	return true;
}

bool PolarTLSServer::loadKey(std::string key_file_path)
{
	if(!init())
		logError("loadKey() could not begin: init() failed.");
	
	memset(&our_private_key, 0, sizeof(our_private_key));
	
	int ret;
	if(access(key_file_path.c_str(), R_OK) != -1)
		ret = pk_parse_keyfile(&our_private_key, key_file_path.c_str(), 0);
	else
	{
		logError("The key file is corrupted or missing from "+key_file_path+"!\n");
		x509_crt_free(&our_cert);
		return false;
	}
	if(ret < 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to parse the key: pk_parse_keyfile returned:", ret);
		x509_crt_free(&our_cert);
		return false;
	}
	
	keyfile_loaded = true;
	if(crtfile_loaded && keyfile_loaded)
		certificate_loaded = true;
	return true;
}
	
bool PolarTLSServer::acceptTLS(int client_socket)
{
	tcp_socket = client_socket;
	
	if(!initialized || !certificate_loaded)
	{
		logError(!initialized ? 
				"An unititialized PolarTLSServer tried to accept a session!" : 
				"A PolarTLSServer without its key+cert loaded tried to accept a session!");
		return false;
	}

	ssl_set_endpoint(&ssl, SSL_IS_SERVER);
	ssl_set_authmode(&ssl, SSL_VERIFY_NONE);
	ssl_set_rng(&ssl, ctr_drbg_random, &polar_tls_ctr_drbg);
	//ssl_set_dbg(&ssl, my_debug, stderr);
	ssl_set_bio(&ssl, net_recv, &tcp_socket, net_send, &tcp_socket);
	ssl_set_ca_chain(&ssl, our_cert.next, NULL, NULL);
	
	int ret;
	if((ret = ssl_set_own_cert(&ssl, &our_cert, &our_private_key)) != 0)
	{
		logErrorFromPolarSSLCode("Failed to set key and cert: ssl_set_own_cert returned:", ret);
		ssl_free(&ssl);
		net_close(tcp_socket);
		tcp_socket = -1;
		return false;
	}
	while((ret = ssl_handshake(&ssl)) != 0)
	{
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			logErrorFromPolarSSLCode("PolarSSL's handshake with server failed: ssl_handshake returned:", ret);
			ssl_free(&ssl);
			net_close(tcp_socket);
			tcp_socket = -1;
			return false;
		}
	}
	connected = true;
	return true;
}

PolarTLSServer::PolarTLSServer()
{
	x509_crt_init(&our_cert);
	//pk_context can just be parsed into; no init needed.
	crtfile_loaded = false;
	keyfile_loaded = false;
	initialized = false;
}

PolarTLSServer::~PolarTLSServer()
{
	if(connected)
		shutdownTLS();
	if(certificate_loaded)
		pk_free(&our_private_key);
	x509_crt_free(&our_cert);
}

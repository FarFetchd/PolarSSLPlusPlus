#include <unistd.h>
#include <string>

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "polarssl/ctr_drbg.h"
#include "polarssl/net.h"

#ifndef POLARSSL_CERTS_C
#error PolarSSL doesnt have certificate support compiled in!!! We need that!
#endif

#include "polar_tls_client.h"

PolarTLSClient::PolarTLSClient()
{
	x509_crt_init(&partner_cert);
	x509_crt_init(&root_certs);
	expected_cname = std::string("");
	initialized = false;
}

PolarTLSClient::~PolarTLSClient()
{
	if(connected)
		shutdownTLS();
	x509_crt_free(&partner_cert);
	x509_crt_free(&root_certs);
}


//NOTE: on ubuntu, root_certs_directory should be "/usr/share/ca-certificates/mozilla"
bool PolarTLSClient::setRootCerts(std::string root_certs_directory)
{
	if(!init())
		logError("setRootCerts() could not begin: init() failed.");
	
	if(x509_crt_parse_path(&root_certs, root_certs_directory.c_str()))
	{
		logError("Error loading root certificates.");
		return false;
	}
	
	using_root_certs = true;
	certificate_loaded = true;
	return true;
}

bool PolarTLSClient::setServerCert(std::string partner_cert_file_path)
{
	if(!init())
		logError("setServerCert() could not begin: init() failed.");
	
	int ret;
	if(access(partner_cert_file_path.c_str(), R_OK) == 0)
		ret = x509_crt_parse_file(&partner_cert, partner_cert_file_path.c_str());
	else
	{
		logError("Error initiating a TLS connection: "+partner_cert_file_path+" not found!");
		return false;
	}
	if(ret < 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to parse the certificate: x509_crt_parse returned:", ret);
		return false;
	}
	
	using_root_certs = false;
	certificate_loaded = true;
	return true;
}

bool PolarTLSClient::connectTLS(std::string hostname, int port)
{
	if(!initialized || !certificate_loaded)
	{
		logError(initialized ? "A PolarTLSClient without server cert loaded called connectTLS()!"
						 : "An unititialized PolarTLSClient called connectTLS()!");
		return false;
	}
	
	int ret = net_connect(&tcp_socket, hostname.c_str(), port);
	
	if(ret != 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to initialize a session: net_connect returned:", ret);
		return false;
	}
	
	if(expected_cname.length() == 0)
		expected_cname = hostname;

	ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ssl, SSL_VERIFY_REQUIRED);
	if(using_root_certs)
		ssl_set_ca_chain(&ssl, &root_certs, NULL, expected_cname.c_str());
	else //!using_root_certs ==> we want to see a single, specific public key; CNAME doesn't matter
		ssl_set_ca_chain(&ssl, &partner_cert, NULL, NULL);
	ssl_set_rng(&ssl, ctr_drbg_random, &polar_tls_ctr_drbg);
	ssl_set_bio(&ssl, net_recv, &tcp_socket, net_send, &tcp_socket);

	while((ret = ssl_handshake(&ssl)) != 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			net_close(tcp_socket);
			tcp_socket = -1;
			logErrorFromPolarSSLCode(
				"PolarSSL's handshake with directory server failed: ssl_handshake returned:",ret);
			return false;
		}

	if((ret = ssl_get_verify_result(&ssl)) != 0)
	{
		std::string all_errors;
		
		if((ret & BADCERT_EXPIRED) != 0)
			all_errors += "Certificate has expired.\n";
		if((ret & BADCERT_REVOKED) != 0)
			all_errors += "Certificate has been revoked.\n";
		if((ret & BADCERT_CN_MISMATCH) != 0)
			all_errors += "Certificate does not match; expected "+expected_cname+".\n";
		if((ret & BADCERT_NOT_TRUSTED) != 0)
			all_errors += "Certificate is not in our trusted list.\n";
		if((ret & (BADCERT_NOT_TRUSTED | BADCERT_CN_MISMATCH | BADCERT_REVOKED | BADCERT_EXPIRED)) == 0)
			all_errors += "An unknown error occurred during certificate verification.";
		
		net_close(tcp_socket);
		tcp_socket = -1;
		logError(all_errors);
		return false;
	}
	connected = true;
	return true;
}

bool PolarTLSClient::handshakeTLS(int connected_socket)
{
	tcp_socket = connected_socket;
	
	if(!initialized || !certificate_loaded)
	{
		net_close(tcp_socket);
		tcp_socket = -1;
		logError(initialized ? "A PolarTLSClient without server cert loaded called handshakeTLS()!"
						 : "An unititialized PolarTLSClient called handshakeTLS()!");
		return false;
	}
	
	if(using_root_certs && expected_cname.length() == 0)
	{
		net_close(tcp_socket);
		tcp_socket = -1;
		logError("Called handshakeTLS() in root-certs-mode without setting expected_cname!");
		return false;
	}
	
	ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ssl, SSL_VERIFY_REQUIRED);
	if(using_root_certs)
		ssl_set_ca_chain(&ssl, &root_certs, NULL, expected_cname.c_str());
	else //!using_root_certs ==> we want to see a single, specific public key; CNAME doesn't matter
		ssl_set_ca_chain(&ssl, &partner_cert, NULL, NULL);
	ssl_set_rng(&ssl, ctr_drbg_random, &polar_tls_ctr_drbg);
	ssl_set_bio(&ssl, net_recv, &tcp_socket, net_send, &tcp_socket);

	int ret;
	while((ret = ssl_handshake(&ssl)) != 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			net_close(tcp_socket);
			tcp_socket = -1;
			logErrorFromPolarSSLCode(
				"PolarSSL's handshake with directory server failed: ssl_handshake returned:",ret);
			return false;
		}

	if((ret = ssl_get_verify_result(&ssl)) != 0)
	{
		std::string all_errors;
		
		if((ret & BADCERT_EXPIRED) != 0)
			all_errors += "Certificate has expired.\n";
		if((ret & BADCERT_REVOKED) != 0)
			all_errors += "Certificate has been revoked.\n";
		if((ret & BADCERT_CN_MISMATCH) != 0)
			all_errors += "Certificate does not match; expected "+expected_cname+".\n";
		if((ret & BADCERT_NOT_TRUSTED) != 0)
			all_errors += "Certificate presented is not in our trusted list.\n";
		if((ret & (BADCERT_NOT_TRUSTED | BADCERT_CN_MISMATCH | BADCERT_REVOKED | BADCERT_EXPIRED)) == 0)
			all_errors += "An unknown error occurred during certificate verification.";
		
		net_close(tcp_socket);
		tcp_socket = -1;
		logError(all_errors);
		return false;
	}
	connected = true;
	return true;
}

void PolarTLSClient::setServerCNAME(std::string cname)
{
	expected_cname = cname;
}

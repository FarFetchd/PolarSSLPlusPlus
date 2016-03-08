#include <string>
#include <sstream>
#include <iostream>

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "polarssl/net.h"
#include "polarssl/error.h"

#ifdef SHOW_POLARSSL_DEBUG
#include "polarssl/debug.h"
#endif

#ifndef POLARSSL_CERTS_C
#error PolarSSL doesnt have certificate support compiled in!!! We need that!
#endif

#include "polar_tls_session.h"

void PolarTLSSession::logErrorFromPolarSSLCode(std::string extra_comment, int code)
{
	char errbuf[300];
	polarssl_strerror(code, errbuf, 300);
	
	std::stringstream ss;
	ss << std::hex << -code;
	
	logError("====================\n"
			+extra_comment
			+"\nError code -0x"+ss.str()
			+":\n"+std::string(errbuf)
			+"\n====================\n");
}

static void polarSSL_stderrDebug(void *ctx, int level, const char *str)
{
	if(level<4)
		std::cerr << str << std::flush;
}

bool PolarTLSSession::init()
{
	int ret;
	entropy_init(&polar_tls_entropy);
	const char* extra_data = "here_is_some_extra_data";
	if((ret = ctr_drbg_init(&polar_tls_ctr_drbg, entropy_func, &polar_tls_entropy, 
						(const unsigned char*) extra_data, strlen(extra_data))) != 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to initialize PRNG: ctr_drbg_init returned:", ret);
		return false;
	}
	
	memset(&ssl, 0, sizeof(ssl_context));
	if((ret = ssl_init(&ssl)) != 0)
	{
		logErrorFromPolarSSLCode("PolarSSL failed to initialize: ssl_init returned:", ret);
		return false;
	}
	
#ifdef SHOW_POLARSSL_DEBUG
	ssl_set_dbg (&ssl, polarSSL_stderrDebug, NULL);
#endif
	
	initialized = true;
	return true;
}

int PolarTLSSession::sendTLS(const unsigned char* buf, unsigned int len)
{
	if(!connected)
	{
		logError("Attempted sendTLS() on an unconnected PolarTLSSession!");
		return -1;
	}
	
	int ret;
	while((ret = ssl_write(&ssl, buf, len)) <= 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
				shutdownTLS();
			else
			{
				if(tcp_socket != -1)
					net_close(tcp_socket);
				ssl_free(&ssl);
				memset(&ssl, 0, sizeof(ssl_context));
				tcp_socket = -1;
				connected = false;
				initialized = false;
			}
			
			logErrorFromPolarSSLCode("PolarSSL sending failure: ssl_write returned:", ret);
			return ret;
		}
	return ret;
}

int PolarTLSSession::recvTLS(unsigned char* buf, unsigned int len)
{
	if(!connected)
	{
		logError("Attempted recvTLS() on an unconnected PolarTLSSession!");
		return -1;
	}
	
	int ret;
	memset(buf, 0, len);
	while((ret = ssl_read(&ssl, buf, len)) < 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
				return 0; //mimic "recv returns 0 on a shutdown TCP connection"
				
			if(tcp_socket != -1)
				net_close(tcp_socket);
			ssl_free(&ssl);
			memset(&ssl, 0, sizeof(ssl_context));
			tcp_socket = -1;
			connected = false;
			initialized = false;
			
			logErrorFromPolarSSLCode("PolarSSL receiving failure: ssl_read returned:", ret);
			return ret;
		}
	return ret;
}

void PolarTLSSession::shutdownTLS()
{
	if(!connected)
		return;
		
	ssl_close_notify(&ssl);

	if(tcp_socket != -1)
		net_close(tcp_socket);
	ssl_free(&ssl);
	memset(&ssl, 0, sizeof(ssl_context));
	tcp_socket = -1;
	connected = false;
	initialized = false;
}

void PolarTLSSession::logError(std::string the_message)
{
	time_t tempTime;
	time(&tempTime);
	std::string time_string(ctime(&tempTime));
	int newline_ind = time_string.find_first_of('\n');
	if(newline_ind != std::string::npos)
		time_string.erase(newline_ind);
	std::string full_line = time_string+": "+the_message+"\n";
	
	if(log_file != std::string(""))
	{
		FILE* log_writer = fopen(log_file.c_str(), "at");
		fwrite(full_line.c_str(), 1, full_line.length(), log_writer);
		fclose(log_writer);
	}
	else
		std::cerr << full_line << std::endl;
}

void PolarTLSSession::setLogFile(std::string _log_file)
{
	log_file = _log_file;
}

PolarTLSSession::PolarTLSSession()
{
	initialized = false;
	connected = false;
	certificate_loaded = false;
	memset(&ssl, 0, sizeof(ssl));
	tcp_socket = -1;
	log_file = std::string("");
}

PolarTLSSession::~PolarTLSSession()
{
	if(initialized)
		ssl_free(&ssl);
	custom_ctr_drbg_free(&polar_tls_ctr_drbg);
	entropy_free(&polar_tls_entropy);
}

//------------------------------------------------------------------
//ctr_drbg_free(&ctr_drbg)... not in the standard ubuntu package

//Implementation that should never be optimized out by the compiler
void PolarTLSSession::custom_polarssl_zeroize( void *v, size_t n )
{
	volatile unsigned char* p = (volatile unsigned char*)v; 
	while( n-- ) 
		*p++ = 0;
}
void PolarTLSSession::custom_aes_free( aes_context *ctx )
{
	if( ctx == NULL )
		return;
	custom_polarssl_zeroize( ctx, sizeof( aes_context ) );
}
void PolarTLSSession::custom_ctr_drbg_free( ctr_drbg_context *ctx )
{
	if( ctx == NULL )
		return;
	custom_aes_free( &ctx->aes_ctx );
	custom_polarssl_zeroize( ctx, sizeof( ctr_drbg_context ) );
}
//------------------------------------------------------------------

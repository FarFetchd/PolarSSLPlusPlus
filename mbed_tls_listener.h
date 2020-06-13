#ifndef _INCLGUARD_MBEDPLUSPLUS_TLS_SERVER_H_
#define _INCLGUARD_MBEDPLUSPLUS_TLS_SERVER_H_

#include <string>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/pk.h"
#include "mbed_tls_session.h"


class MbedTLSServer : public MbedTLSSession
{
public:

  //Must call both loadCert() and loadKey() before acceptTLS().
  bool loadCert(std::string cert_file_path);
  bool loadKey(std::string key_file_path);

  //client_socket should be a connected TCP socket, accepted by accept()
  //(or by MbedTLS's net_accept() or something like that). If this function
  //returns true, then you have a working TLS session, and you can call
  //sendTLS(), recvTLS(), and shutdownTLS() on it! Hooray!
  bool acceptTLS(int client_socket);





  MbedTLSServer();
  ~MbedTLSServer();
private:
  mbedtls_x509_crt our_cert;
  mbedtls_pk_context our_private_key;

  bool crtfile_loaded;
  bool keyfile_loaded;
};

#endif //_INCLGUARD_MBEDPLUSPLUS_TLS_SERVER_H_




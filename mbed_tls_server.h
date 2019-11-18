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
  // All std::optional<std::string> are nullopt for success, or error message.

  //Must call both loadCert() and loadKey() before acceptTLS().
  std::optional<std::string> loadCert(std::string cert_file_path);
  std::optional<std::string> loadKey(std::string key_file_path);

  //client_socket should be a connected TCP socket, accepted by accept()
  //(or by MbedTLS's net_accept() or something like that). If this function
  //returns true, then you have a working TLS session, and you can call
  //sendTLS(), recvTLS(), and shutdownEverything() on it! Hooray!
  std::optional<std::string> acceptTLS(int client_socket);
  // acceptTLS for mbedtls_net_context gotten from mbedtls_net_accept().
  // Takes ownership of the passed pointer (will destroy).
  std::optional<std::string> acceptTLS(mbedtls_net_context* client_socket);




  MbedTLSServer();
  ~MbedTLSServer();
protected:
  void initMbedConfig() override;
private:
  std::optional<std::string> acceptTLSinternal();
  mbedtls_x509_crt our_cert_;
  mbedtls_pk_context our_private_key_;

  bool crtfile_loaded_;
  bool keyfile_loaded_;
};

#endif //_INCLGUARD_MBEDPLUSPLUS_TLS_SERVER_H_

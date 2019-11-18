#ifndef _INCLGUARD_MBEDPLUSPLUS_TLS_SESSION_H_
#define _INCLGUARD_MBEDPLUSPLUS_TLS_SESSION_H_

#include <optional>
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

class MbedTLSSession
{
public:
  //Both the client and server subclasses can use these as if they were the
  //send() and recv() functions of TCP sockets. They return number of bytes
  //send/received, recv() returns 0 if the other side closed gracefully.
  //recv() blocks if nothing to receive yet, send() blocks if buffer full.
  int sendTLS(const unsigned char* buf, unsigned int len);
  int recvTLS(unsigned char* buf, unsigned int len);

  //Like close() for TCP sockets.
  void shutdownEverything();

  // Get it ready for connecting or accepting.
  // Returns nullopt on success, error description on failure.
  std::optional<std::string> init();





MbedTLSSession();
  ~MbedTLSSession();

protected:
  virtual void initMbedGeneral();
  virtual void initMbedConfig() = 0;
  
  mbedtls_ssl_context ssl_;
  mbedtls_net_context tcp_socket_;
  bool initialized_;
  bool certificate_loaded_;
  bool tls_connected_;

  mbedtls_ssl_config mbedtls_config_;
  mbedtls_ctr_drbg_context mbed_tls_ctr_drbg_;
  mbedtls_entropy_context our_entropy_;

  std::string log_file;
};

#endif //_INCLGUARD_MBEDPLUSPLUS_TLS_SESSION_H_

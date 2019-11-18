#include <unistd.h>
#include <string.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/ctr_drbg.h"

#ifndef MBEDTLS_CERTS_C
#error MbedTLS doesnt have certificate support compiled in!!! We need that!
#endif

#include "mbed_tls_server.h"
#include "error.h"

void MbedTLSServer::initMbedConfig()
{
  mbedtls_ssl_config_defaults(&mbedtls_config_, MBEDTLS_SSL_IS_SERVER,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);
}

std::optional<std::string> MbedTLSServer::loadCert(std::string cert_file_path)
{
  if(std::optional<std::string> maybe_err = init(); maybe_err.has_value())
    return maybe_err.value() + " (in loadCert)";

  int ret;
  if(access(cert_file_path.c_str(), R_OK) == 0)
    ret = mbedtls_x509_crt_parse_file(&our_cert_, cert_file_path.c_str());
  else
  {
    return buildError("The certificate file is corrupted or missing from "
                      +cert_file_path+"!\n");
  }
  if(ret < 0)
  {
    return buildError(errorFromMbedTLSCode(
        "MbedTLS failed to parse the certificate: x509_crt_parse returned:",
        ret));
  }

  crtfile_loaded_ = true;
  if(crtfile_loaded_ && keyfile_loaded_)
    certificate_loaded_ = true;
  return std::nullopt;
}

std::optional<std::string> MbedTLSServer::loadKey(std::string key_file_path)
{
  if(std::optional<std::string> maybe_err = init(); maybe_err.has_value())
    return maybe_err.value() + " (in loadKey)";

  memset(&our_private_key_, 0, sizeof(our_private_key_));

  int ret;
  if(access(key_file_path.c_str(), R_OK) != -1)
    ret = mbedtls_pk_parse_keyfile(&our_private_key_, key_file_path.c_str(), 0);
  else
  {
    mbedtls_x509_crt_free(&our_cert_);
    return buildError("The key file is corrupted or missing from "+
                      key_file_path+"!\n");
  }
  if(ret < 0)
  {
    mbedtls_x509_crt_free(&our_cert_);
    return buildError(errorFromMbedTLSCode(
        "MbedTLS failed to parse the key: pk_parse_keyfile returned:", ret));
  }

  keyfile_loaded_ = true;
  if(crtfile_loaded_ && keyfile_loaded_)
    certificate_loaded_ = true;
  return std::nullopt;
}

std::optional<std::string> MbedTLSServer::acceptTLSinternal()
{
  if (!initialized_)
  {
    return buildError("An unititialized MbedTLSServer tried to "
                      "accept a session!");
  }
  if (!certificate_loaded_)
  {
     return buildError("A MbedTLSServer without its key+cert loaded "
                       "tried to accept a session!");
  }

  mbedtls_ssl_set_bio(&ssl_, &tcp_socket_,
                      mbedtls_net_send, mbedtls_net_recv,
                      mbedtls_net_recv_timeout);

  int ret;
  if((ret = mbedtls_ssl_set_hs_own_cert(&ssl_, &our_cert_, &our_private_key_))
      != 0)
  {
    shutdownEverything();
    return buildError(errorFromMbedTLSCode(
        "Failed to set key and cert: ssl_set_own_cert returned:", ret));
  }
  while((ret = mbedtls_ssl_handshake(&ssl_)) != 0)
  {
    if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      shutdownEverything();
      return buildError(errorFromMbedTLSCode(
          "MbedTLS's handshake with client failed: ssl_handshake returned:",
          ret));
    }
  }
  tls_connected_ = true;
  return std::nullopt;
}

std::optional<std::string> MbedTLSServer::acceptTLS(int client_socket)
{
  mbedtls_net_init(&tcp_socket_);
  tcp_socket_.fd = client_socket;
  return acceptTLSinternal();
}

std::optional<std::string> MbedTLSServer::
acceptTLS(mbedtls_net_context* client_socket)
{
  memcpy(&tcp_socket_, client_socket, sizeof(mbedtls_net_context));
  return acceptTLSinternal();
}

MbedTLSServer::MbedTLSServer()
{
  mbedtls_x509_crt_init(&our_cert_);
  //pk_context can just be parsed into; no init needed.
  crtfile_loaded_ = false;
  keyfile_loaded_ = false;
  initialized_ = false;
}

MbedTLSServer::~MbedTLSServer()
{
  if(certificate_loaded_)
    mbedtls_pk_free(&our_private_key_);
  mbedtls_x509_crt_free(&our_cert_);
}

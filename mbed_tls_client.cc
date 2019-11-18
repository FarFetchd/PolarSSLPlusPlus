#include <unistd.h>
#include <string>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#ifndef MBEDTLS_CERTS_C
#error MbedTLS doesnt have certificate support compiled in!!! We need that!
#endif

#include "error.h"
#include "mbed_tls_client.h"

// NOTE: see
// https://tls.mbed.org/api/compat-1_83_8h.html for PolarSSL name translation

std::optional<std::string> MbedTLSClient::
connectRootSigned(std::string hostname, int port, std::string cname,
                  std::string root_certs_dir)
{
  if (auto maybe_err = init(); maybe_err.has_value())
    return maybe_err;

  if (cname.empty())
    cname = hostname;

  if(int ret = mbedtls_net_connect(&tcp_socket_, hostname.c_str(),
                                   std::to_string(port).c_str(),
                                   MBEDTLS_NET_PROTO_TCP); 
     ret != 0)
  {
    return errorFromMbedTLSCode(
      "MbedTLS failed to initialize a session: net_connect returned:", ret);
  }

  mbedtls_x509_crt root_certs;
  mbedtls_x509_crt_init(&root_certs);
  if(mbedtls_x509_crt_parse_path(&root_certs, root_certs_dir.c_str()))
    return "Error loading root certificates.";

  return doHandshake(&root_certs);
}

std::optional<std::string> MbedTLSClient::
connectSpecificCert(std::string hostname, int port, std::string cert_filepath)
{
  if (auto maybe_err = init(); maybe_err.has_value())
    return maybe_err;

  std::string port_str = std::to_string(port);
  if(int ret = mbedtls_net_connect(&tcp_socket_, hostname.c_str(),
                                   port_str.c_str(), MBEDTLS_NET_PROTO_TCP);
     ret != 0)
  {
    return errorFromMbedTLSCode(
      "MbedTLS failed to initialize a session: net_connect returned:", ret);
  }

  if(access(cert_filepath.c_str(), R_OK) != 0)
    return buildError("Can't access file "+cert_filepath);

  mbedtls_x509_crt partner_cert;
  mbedtls_x509_crt_init(&partner_cert);

  if(int ret = mbedtls_x509_crt_parse_file(&partner_cert,
                                           cert_filepath.c_str());
     ret < 0)
  {
    return errorFromMbedTLSCode(
      "MbedTLS failed to parse the certificate: x509_crt_parse returned:", ret);
  }

  return doHandshake(&partner_cert);
}

std::optional<std::string> MbedTLSClient::
handshakeRootSigned(int fd, std::string cname, std::string root_certs_dir)
{
  if (cname.empty())
    return buildError("CNAME needed!");

  if (auto maybe_err = init(); maybe_err.has_value())
    return maybe_err;

  tcp_socket_.fd = fd;

  mbedtls_x509_crt root_certs;
  mbedtls_x509_crt_init(&root_certs);
  if(mbedtls_x509_crt_parse_path(&root_certs, root_certs_dir.c_str()))
    return buildError("Error loading root certificates.");

  return doHandshake(&root_certs);
}

std::optional<std::string> MbedTLSClient::
handshakeSpecificCert(int fd, std::string cert_filepath)
{
  if (auto maybe_err = init(); maybe_err.has_value())
    return maybe_err;
  
  tcp_socket_.fd = fd;

  if(access(cert_filepath.c_str(), R_OK) != 0)
    return buildError("Can't access file "+cert_filepath);
  
  
  mbedtls_x509_crt partner_cert;
  mbedtls_x509_crt_init(&partner_cert);
  if(int ret = mbedtls_x509_crt_parse_file(&partner_cert,
                                           cert_filepath.c_str());
     ret < 0)
  {
    return errorFromMbedTLSCode(
      "MbedTLS failed to parse the certificate: x509_crt_parse returned:", ret);
  }
  return doHandshake(&partner_cert);
}

std::optional<std::string> MbedTLSClient::
doHandshake(mbedtls_x509_crt* cert_or_cert_chain)
{
  mbedtls_ssl_conf_endpoint(&mbedtls_config_, MBEDTLS_SSL_IS_CLIENT);
  mbedtls_ssl_conf_authmode(&mbedtls_config_, MBEDTLS_SSL_VERIFY_REQUIRED);
  // TODO that third NULL is for revocation lists, which we ideally would handle
  // ... but what mechanism to ingest them?
  mbedtls_ssl_conf_ca_chain(&mbedtls_config_, cert_or_cert_chain, NULL);
  mbedtls_ssl_conf_rng(&mbedtls_config_,
                       mbedtls_ctr_drbg_random, &mbed_tls_ctr_drbg_);
  mbedtls_ssl_set_bio(&ssl_, &tcp_socket_, mbedtls_net_send, mbedtls_net_recv,
                      NULL);
  int ret;
  while((ret = mbedtls_ssl_handshake(&ssl_)) != 0)
  {
    if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      mbedtls_net_free(&tcp_socket_);
      mbedtls_x509_crt_free(cert_or_cert_chain);
      return errorFromMbedTLSCode(
        "MbedTLS's handshake with directory server failed: "
        "ssl_handshake returned:",ret);
    }
  }
  if((ret = mbedtls_ssl_get_verify_result(&ssl_)) != 0)
  {
    std::string all_errors;
    if((ret & MBEDTLS_X509_BADCERT_EXPIRED) != 0)
      all_errors += "Certificate has expired.\n";
    if((ret & MBEDTLS_X509_BADCERT_REVOKED) != 0)
      all_errors += "Certificate has been revoked.\n";
    if((ret & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0)
      all_errors += "Certificate does not match CNAME\n";
    if((ret & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0)
      all_errors += "Certificate presented is not in our trusted list.\n";
    if((ret & (MBEDTLS_X509_BADCERT_NOT_TRUSTED |
               MBEDTLS_X509_BADCERT_CN_MISMATCH |
               MBEDTLS_X509_BADCERT_REVOKED |
               MBEDTLS_X509_BADCERT_EXPIRED)) == 0)
    {
      all_errors += "Unknown error during certificate verification.";
    }
    mbedtls_net_free(&tcp_socket_);
    mbedtls_x509_crt_free(cert_or_cert_chain);
    return all_errors;
  }
  mbedtls_x509_crt_free(cert_or_cert_chain);
  tls_connected_ = true;
  return std::nullopt;
}

void MbedTLSClient::initMbedConfig()
{
  mbedtls_ssl_config_defaults(&mbedtls_config_, MBEDTLS_SSL_IS_CLIENT,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);
}

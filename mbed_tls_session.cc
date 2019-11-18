#include <cstring>
#include <string>
#include <iostream>
#include <unistd.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#ifdef SHOW_MBEDTLS_DEBUG
#include "mbedtls/debug.h"
#endif

#ifndef MBEDTLS_CERTS_C
#error MbedTLS doesnt have certificate support compiled in!!! We need that!
#endif

#include "error.h"
#include "mbed_tls_session.h"

static void polarSSL_stderrDebug(void *ctx, int level, const char *str)
{
  if(level<4)
    std::cerr << str << std::flush;
}

void MbedTLSSession::initMbedGeneral()
{
  // TODO I think this is supposed to be program-wide, so doing one per
  //      session is probably inefficient?
  mbedtls_entropy_init(&our_entropy_);
  mbedtls_ssl_config_init(&mbedtls_config_);
  initMbedConfig();
  mbedtls_ssl_conf_rng(&mbedtls_config_, mbedtls_ctr_drbg_random,
                       &mbed_tls_ctr_drbg_);
}

std::optional<std::string> MbedTLSSession::init()
{
  if(initialized_)
    return std::nullopt;
  
  initMbedGeneral();

  mbedtls_net_init(&tcp_socket_);
  int ret;
  
  mbedtls_ctr_drbg_init(&mbed_tls_ctr_drbg_);
  const char* extra_data = "TODO i should be e.g. device serial number";
  if((ret = mbedtls_ctr_drbg_seed(
                &mbed_tls_ctr_drbg_, mbedtls_entropy_func, 
                &our_entropy_,
                (const unsigned char*) extra_data, strlen(extra_data))) != 0)
  {
    return errorFromMbedTLSCode(
        "MbedTLS failed to initialize PRNG: ctr_drbg_init returned:", ret);
  }

  memset(&ssl_, 0, sizeof(mbedtls_ssl_context));
  mbedtls_ssl_init(&ssl_);
  if((ret = mbedtls_ssl_setup(&ssl_, &mbedtls_config_)) != 0)
  {
    return errorFromMbedTLSCode(
        "MbedTLS failed to initialize: ssl_init returned:", ret);
  }

#ifdef SHOW_MBEDTLS_DEBUG
  mbedtls_ssl_set_dbg (&ssl_, polarSSL_stderrDebug, NULL);
#endif

  initialized_ = true;
  return std::nullopt;
}

int MbedTLSSession::sendTLS(const unsigned char* buf, unsigned int len)
{
  if(!tls_connected_)
  {
    logError("Attempted sendTLS() on an unconnected MbedTLSSession!");
    return -1;
  }

  int ret;
  while((ret = mbedtls_ssl_write(&ssl_, buf, len)) <= 0)
    if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      shutdownEverything();

      logErrorFromMbedTLSCode(
          "MbedTLS sending failure: ssl_write returned:", ret);
      return ret;
    }
  return ret;
}

int MbedTLSSession::recvTLS(unsigned char* buf, unsigned int len)
{
  if(!tls_connected_)
  {
    logError("Attempted recvTLS() on an unconnected MbedTLSSession!");
    return -1;
  }

  int ret;
  memset(buf, 0, len);
  while((ret = mbedtls_ssl_read(&ssl_, buf, len)) < 0)
    if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0; //mimic "recv returns 0 on a shutdown TCP connection"

      shutdownEverything();

      logErrorFromMbedTLSCode(
          "MbedTLS receiving failure: ssl_read returned:", ret);
      return ret;
    }
  return ret;
}

MbedTLSSession::MbedTLSSession()
{
  initialized_ = false;
  tls_connected_ = false;
  certificate_loaded_ = false;
  memset(&ssl_, 0, sizeof(ssl_));
}

void MbedTLSSession::shutdownEverything()
{
  if(tls_connected_)
    mbedtls_ssl_close_notify(&ssl_);
  if(tcp_socket_.fd != -1)
  {
    mbedtls_net_free(&tcp_socket_); // NOTE this is also a shutdown().
    tcp_socket_.fd = -1;
  }
  tls_connected_ = false;
  if(initialized_)
  {
    mbedtls_ssl_free(&ssl_);
    memset(&ssl_, 0, sizeof(mbedtls_ssl_context));
    mbedtls_ssl_config_free(&mbedtls_config_);
    mbedtls_ctr_drbg_free(&mbed_tls_ctr_drbg_);
    mbedtls_entropy_free(&our_entropy_);
    initialized_ = false;
  }
}

MbedTLSSession::~MbedTLSSession()
{
  shutdownEverything();
}

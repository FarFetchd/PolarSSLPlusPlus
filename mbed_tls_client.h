#ifndef _INCLGUARD_MBEDPLUSPLUS_TLS_CLIENT_H_
#define _INCLGUARD_MBEDPLUSPLUS_TLS_CLIENT_H_

#include <optional>
#include <string>

#include "mbed_tls_session.h"

class MbedTLSClient : public MbedTLSSession
{
public:

//Functions that attempt to establish a TLS session, making this MbedTLSClient
//(basically just an MbedTLSSession) ready to go if successful.
//These functions return nullopt on success, or an error reason on failure.

//Connects to hostname:port, which must have a valid cert signed by a chain
//back to a root cert. Leave cname as "" to expect the CNAME to be hostname.
std::optional<std::string> connectRootSigned(
  std::string hostname, int port,
  std::string cname = "",
  std::string root_certs_dir = "/usr/share/ca-certificates/mozilla");

//Connects to hostname:port, which must be using the cert in cert_filepath.
std::optional<std::string> connectSpecificCert(
  std::string hostname, int port,
  std::string cert_filepath);

//Does a TLS handshake on an existing TCP conneciton. You must specify CNAME.
//Verifies that the server has a valid root-signed cert for CNAME.
std::optional<std::string> handshakeRootSigned(
  int fd,
  std::string cname,
  std::string root_certs_dir = "/usr/share/ca-certificates/mozilla");

//Does a TLS handshake on an existing TCP conneciton.
//Verifies that the server has the cert specified by cert_filepath.
std::optional<std::string> handshakeSpecificCert(
  int fd,
  std::string cert_filepath);

protected:
  void initMbedConfig() override;

private:
std::optional<std::string> doHandshake(mbedtls_x509_crt* cert_or_cert_chain);

};

#endif //_INCLGUARD_MBEDPLUSPLUS_TLS_CLIENT_H_

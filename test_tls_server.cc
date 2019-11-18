#include <iostream>
#include <cstring>

using std::cout;
using std::cerr;
using std::endl;

#include "mbedtls/net_sockets.h"

#include "mbed_tls_server.h"

int main()
{
  MbedTLSServer server;
  if (auto maybe_err = server.loadCert("the_servers_cert.crt");
      maybe_err.has_value())
  {
    cerr << "Failed to load server cert: " << maybe_err.value();
    return 1;
  }
  if (auto maybe_err = server.loadKey("the_servers_key.key");
      maybe_err.has_value())
  {
    cerr << "Failed to load server key: " << maybe_err.value();
    return 1;
  }

  int ret;
  mbedtls_net_context listen_socket;
  mbedtls_net_init(&listen_socket);
  if((ret = mbedtls_net_bind(&listen_socket, "127.0.0.1", "7777",
                             MBEDTLS_NET_PROTO_TCP)) != 0)
  {
    cerr << "bind() and listen() failure." << endl;
    return 1;
  }
  mbedtls_net_context accepted_socket;
  mbedtls_net_accept(&listen_socket, &accepted_socket, NULL, 0, NULL);

  if (auto maybe_err = server.acceptTLS(&accepted_socket);
      maybe_err.has_value())
  {
    cerr << "Failed to accept TLS handshake: " << maybe_err.value();
    return 1;
  }

  unsigned char client_says[100]; memset(client_says, 0, 100);
  std::string server_says("Hello to you too!");
  server.recvTLS(client_says, 99); client_says[99]=0;
  server.sendTLS((const unsigned char*)server_says.c_str(),
                 server_says.length());

  //NOTE: could explicitly call server.shutdownTLS() here, but it's ok not to;
  //    the dtor will call it for us.

  cout << client_says << endl;
}

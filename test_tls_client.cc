#include <iostream>
#include <cstring>

using std::cout;
using std::endl;

#include "mbed_tls_client.h"


void clientToGoogle()
{
  cout << "=================CLIENT TO GOOGLE================" << endl;

  MbedTLSClient client;
  if (auto maybe_err = client.connectRootSigned("google.com", 443);
      maybe_err.has_value())
  {
    cout << maybe_err.value();
    return;
  }

  std::string get_google("GET / HTTP/1.0\r\n\r\n");
  client.sendTLS((const unsigned char*)get_google.c_str(), get_google.length());
  unsigned char buf[100]; memset(buf, 0, 100);
  client.recvTLS(buf, 99); buf[99] = 0;
  cout << buf << endl;

  //NOTE: could also just let it go out of scope; dtor would call shutdown.
  client.shutdownEverything();
  cout << "===============END CLIENT TO GOOGLE==============\n\n" << endl;
}

void clientToGoogleDelayedHandshake()
{
  cout << "=================CLIENT TO GOOGLE2===============" << endl;

  
  mbedtls_net_context tcp_socket;
  if(int ret = mbedtls_net_connect(&tcp_socket, "www.google.com", "443",
                                   MBEDTLS_NET_PROTO_TCP);
     ret != 0)
  {
    cout << "mbedtls_net_connect failed with code " << ret << endl;
    return;
  }

  //NOTE: handshakeTLS() is useful in the case where some communication
  //happens in between the TCP connection being established, and the two
  //sides wanting to establish TLS. This pointless use of it is just a demo!


  // NOTE: /usr/share/ca-certificates/mozilla would anyways be the default value
  // if the argument was left out.
  MbedTLSClient client;
  if (auto maybe_err = client.handshakeRootSigned(
    tcp_socket.fd, "www.google.com", "/usr/share/ca-certificates/mozilla");
    maybe_err.has_value())
  {
    cout << maybe_err.value();
    return;
  }

  std::string get_google("GET / HTTP/1.0\r\n\r\n");
  client.sendTLS((const unsigned char*)get_google.c_str(), get_google.length());
  unsigned char buf[100]; memset(buf, 0, 100);
  client.recvTLS(buf, 99); buf[99] = 0;
  cout << buf << endl;

  //NOTE: could also just let it go out of scope; dtor would call shutdown.
  client.shutdownEverything();
  cout << "===============END CLIENT TO GOOGLE2=============\n\n" << endl;

}

void clientToSelf()
{
  cout << "==================CLIENT TO SELF=================" << endl;

  MbedTLSClient client;
  if (auto maybe_err = client.connectSpecificCert("localhost", 7777,
                                                  "the_servers_cert.crt");
      maybe_err.has_value())
  {
    cout << maybe_err.value();
    return;
  }

  std::string say_hello("Hello there!");
  client.sendTLS((const unsigned char*)say_hello.c_str(), say_hello.length());
  unsigned char buf[100]; memset(buf, 0, 100);
  client.recvTLS(buf, 99); buf[99] = 0;
  cout << buf << endl;

  //NOTE: could also just let it go out of scope; dtor would call shutdown.
  client.shutdownEverything();
  cout << "================END CLIENT TO SELF===============\n\n\n" << endl;
}

int main()
{
  clientToGoogle();
  clientToGoogleDelayedHandshake();

  //be sure test_tls_server is already running!
  clientToSelf();
}


.PHONY: test clean

test: test_tls_server test_tls_client

test_tls_server: test_tls_server.cc mbed_tls_session.cc mbed_tls_server.cc error.cc
	g++ -std=c++17 -o test_tls_server test_tls_server.cc mbed_tls_session.cc mbed_tls_server.cc error.cc -lmbedtls -lmbedx509 -lmbedcrypto

test_tls_client: test_tls_client.cc mbed_tls_session.cc mbed_tls_client.cc error.cc
	g++ -std=c++17 -o test_tls_client test_tls_client.cc mbed_tls_session.cc mbed_tls_client.cc error.cc -lmbedtls -lmbedx509 -lmbedcrypto

clean:
	rm -f test_tls_server test_tls_client

.PHONY: test clean

test: test_tls_server test_tls_client

test_tls_server: test_tls_server.cc polar_tls_session.cc polar_tls_server.cc
	g++ -o test_tls_server test_tls_server.cc polar_tls_session.cc polar_tls_server.cc -lpolarssl

test_tls_client: test_tls_client.cc polar_tls_session.cc polar_tls_client.cc
	g++ -o test_tls_client test_tls_client.cc polar_tls_session.cc polar_tls_client.cc -lpolarssl

clean:
	rm -f test_tls_server test_tls_client

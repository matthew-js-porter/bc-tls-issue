package com.example.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.web.servlet.client.RestTestClient;

import javax.net.ssl.SSLParameters;
import java.net.http.HttpClient;
import java.security.Security;

@SpringBootTest(
		properties = {
				"spring.ssl.bundle.jks.client.truststore.location=classpath:keystore/keystore.p12",
				"spring.ssl.bundle.jks.client.truststore.password=password",
		},
		webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT
)
class TLSApplicationTests {

	@Autowired
	SslBundles sslBundles;

	@AfterEach
	void tearDown() {
		if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) != null) {
			Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
		}
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"})
	void defaultJsseProvider(final String cipher) {
		final SslBundle sslBundle  = sslBundles.getBundle("client");
		final HttpClient httpClient = buildWithCipher(sslBundle, cipher);
		final RestTestClient restTestClient = RestTestClient.bindToServer(new JdkClientHttpRequestFactory(httpClient))
				.baseUrl("https://localhost:8443")
				.build();
		restTestClient.get().uri("/actuator/info").exchange().expectStatus().is2xxSuccessful();
	}

	@ParameterizedTest
	@ValueSource(strings = {"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"})
	void bcJsseProvider(final String cipher) {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
		final SslBundle sslBundle  = sslBundles.getBundle("client");
		final HttpClient httpClient = buildWithCipher(sslBundle, cipher);
		final RestTestClient restTestClient = RestTestClient.bindToServer(new JdkClientHttpRequestFactory(httpClient))
				.baseUrl("https://localhost:8443")
				.build();
		restTestClient.get().uri("/actuator/info").exchange().expectStatus().is2xxSuccessful();
	}

	private HttpClient buildWithCipher(final SslBundle sslBundle, final String cipher) {
		final SSLParameters sslParameters = new SSLParameters();
		sslParameters.setCipherSuites(new String[] {cipher});
		sslParameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
		return HttpClient.newBuilder()
				.sslContext(sslBundle.createSslContext())
				.sslParameters(sslParameters)
				.build();
	}
}
package com.jp.ssl.controller;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;



@RestController
public class SslClientController {
	
	@Value("${server.ssl.trust-policy}")
	private String trustPolicy;
	
	@Value("${server.ssl.trust-store}")
    private Resource trustStore;
    
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;
	
	@GetMapping(value = "/sslclient")
    public String callSslServer() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException {

		System.out.println("Call to SSL Client");
		
		HttpHeaders headers = new HttpHeaders();
		HttpEntity<?> requestEntity =  new HttpEntity<>(headers);


        RestTemplate restTemplate = null;
        
        if(trustPolicy.equals("truststore"))
        {
        	restTemplate = new RestTemplate(trustStore());
        }
        else
        {
        	restTemplate = new RestTemplate(trustAll());
        }
		
        System.out.println("About to exchange");
		ResponseEntity<String> response = restTemplate.exchange("https://localhost:8443/sslserver", 
					HttpMethod.GET, 
					requestEntity, 
					String.class,
					new HashMap<String, Object>());
		
		System.out.println("Exchanged");

        return response.getBody();

    }
	
	// Effectively bypass  cert authentication, but still run across SSL
	private HttpComponentsClientHttpRequestFactory trustAll() throws NoSuchAlgorithmException, KeyManagementException
	{
		final TrustManager[] UNQUESTIONING_TRUST_MANAGER = new TrustManager[]
				{
				new X509TrustManager() 
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return null;
					}
                  
				public void checkClientTrusted( X509Certificate[] certs, String authType ){}
                public void checkServerTrusted( X509Certificate[] certs, String authType ){}
              }
          };
        
        final SSLContext sc = SSLContext.getInstance("SSL");
        sc.init( null, UNQUESTIONING_TRUST_MANAGER, null );
        
        System.out.println("Trust manager created");
        
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(sc, new NoopHostnameVerifier());
        
        System.out.println("Socket factory");
		
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sf)
        		.build();
        
        System.out.println("HTTP client");
  
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        
        System.out.println("Request factory");
        
        return requestFactory;
	}
	
	private HttpComponentsClientHttpRequestFactory trustStore() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException
	{
		final SSLContext sc = new SSLContextBuilder()
				.loadTrustMaterial(trustStore.getURL(), trustStorePassword.toCharArray())
  		      	.build();
		
		SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(sc);
        
        System.out.println("Socket factory");
		
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sf)
        		.build();
        
        System.out.println("HTTP client");
  
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        
        System.out.println("Request factory");
        
        return requestFactory;
	}

}

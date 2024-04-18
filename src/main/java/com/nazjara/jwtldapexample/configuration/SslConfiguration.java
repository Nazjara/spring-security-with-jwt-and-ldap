package com.nazjara.jwtldapexample.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;

@Configuration
@Slf4j
public class SslConfiguration
{
    @Bean
    public SSLContext getSSLContext(@Value("${server.ssl.key-store.path}") String keyStorePath,
                                @Value("${server.ssl.key-store.password}") String keyStorePwd,
                                @Value("${security.ldap.tls.trusted-certificate.path}") String trustedCertPath)
            throws GeneralSecurityException, IOException
    {
        if (!StringUtils.hasText(trustedCertPath))
        {
            return null;
        }

        var certificateFactory = CertificateFactory.getInstance("X.509");
        var certificates = new ArrayList<Certificate>();

        try (var inputStream = new FileInputStream(trustedCertPath))
        {
            certificates.addAll(certificateFactory.generateCertificates(inputStream));
        }

        var keyStore = KeyStore.getInstance(new File(keyStorePath), keyStorePwd.toCharArray());
        var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePwd.toCharArray());

        var trustedKeyStore = createKeyStore(certificates);
        var trustManager = getTrustManager(trustedKeyStore);

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), new TrustManager[] { trustManager }, null);
        SSLContext.setDefault(sslContext);
        return sslContext;
    }

    private KeyStore createKeyStore(Collection<Certificate> certificates) throws KeyStoreException {
        var keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        try
        {
            keystore.load(null, null);
        } catch (IOException | GeneralSecurityException e)
        {
            log.error(String.format("Exception occurred: Creating key store failed: %s", e.getMessage()), e);
        }

        for (Certificate certificate : certificates)
        {
            keystore.setCertificateEntry(certificate.toString(), certificate);
        }

        return keystore;
    }

    private TrustManager getTrustManager(KeyStore keyStore) throws GeneralSecurityException
    {
        var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        var trustManagers = trustManagerFactory.getTrustManagers();
        var maxManagersCount = 1;
        if (trustManagers.length > maxManagersCount)
        {
            throw new GeneralSecurityException(String.format(
                    "Expected 1 TrustManager from TrustManagerFactory(%s), got %s",
                    trustManagerFactory, trustManagers.length));
        }

        var trustManager = trustManagers[0];
        if (!(trustManager instanceof X509TrustManager))
        {
            throw new GeneralSecurityException(String.format(
                    "Expected %s from TrustManagerFactory(%s), got %s",
                    X509TrustManager.class.getCanonicalName(), trustManagerFactory,
                    trustManager.getClass().getCanonicalName()));
        }

        return trustManagers[0];
    }
}

package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class OmniX509ExtendedTrustManagerTest {
    private static final String AUTH_TYPE = "RSA";
    private static final X509Certificate[] CHAIN = new X509Certificate[1];
    private static OmniX509ExtendedTrustManager omniX509ExtendedTrustManager;
    private static OmniTrustManagerFactorySpi omniTrustManagerFactorySpi;
    private static TrustManager[] trustManagers;
    private static KeyStore keyStore;
    @Mock
    private OmniSecurityNotifier notifier;
    @Spy
    private OmniTlsStarterSettings settings = new OmniTlsStarterSettings();

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException {
        X509Certificate x509Certificate = null;
        ClassLoader classLoader = OmniX509ExtendedTrustManagerTest.class.getClassLoader();
        keyStore = KeyStore.getInstance("JKS");
        try (InputStream keyStoreData = classLoader
                .getResourceAsStream("certificates/certificate.p12")) {
            char[] keyStorePassword = "1111".toCharArray();
            keyStore.load(keyStoreData, keyStorePassword);
        }

        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
        }
        CHAIN[0] = x509Certificate;
    }

    @AfterEach
    void cleanUp(){
        trustManagers = null;
        omniX509ExtendedTrustManager = null;
        omniTrustManagerFactorySpi = null;
    }

    @Test
    void wrapOnPropertyInitializedTrustManagerAndNotifierReturnsValidTruestManager() throws KeyStoreException {
        omniTrustManagerFactorySpi = new OmniTrustManagerFactorySpi();
        omniTrustManagerFactorySpi.engineInit(keyStore);
        trustManagers = omniTrustManagerFactorySpi.engineGetTrustManagers();
        Arrays.stream(trustManagers).forEach(t -> assertInstanceOf(OmniX509ExtendedTrustManager.class, t));
    }

    @Test
    void checkServerTrustedThrowsIllegalArgumentException() throws KeyStoreException {
        omniTrustManagerFactorySpi = new OmniTrustManagerFactorySpi();
        omniTrustManagerFactorySpi.engineInit(keyStore);
        trustManagers = omniTrustManagerFactorySpi.engineGetTrustManagers();
        omniX509ExtendedTrustManager = (OmniX509ExtendedTrustManager) trustManagers[0];
        assertDoesNotThrow(() ->
                omniX509ExtendedTrustManager.checkServerTrusted(CHAIN, AUTH_TYPE));
        Exception exception = assertThrows(IllegalArgumentException.class, () -> omniX509ExtendedTrustManager.checkServerTrusted(null, AUTH_TYPE));
        String expectedMessage = "null or zero-length certificate chain";
        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
        expectedMessage = "null or zero-length authentication type";
        exception = assertThrows(IllegalArgumentException.class, () -> omniX509ExtendedTrustManager.checkServerTrusted(CHAIN, null));
        actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
    }

    @Test
    void checkOmniX509ExtendedTrustManagerGetAcceptedIssuersForReturnX509CertificateArray() throws KeyStoreException {
        omniTrustManagerFactorySpi = new OmniTrustManagerFactorySpi();
        omniTrustManagerFactorySpi.engineInit(keyStore);
        trustManagers = omniTrustManagerFactorySpi.engineGetTrustManagers();
        omniX509ExtendedTrustManager = (OmniX509ExtendedTrustManager) trustManagers[0];

        Arrays.stream(omniX509ExtendedTrustManager.getAcceptedIssuers()).forEach(Assertions::assertNotNull);

    }

    @Test
    void wrap() {
        Arrays.stream(Security.getProviders())
                .map(Provider::getServices)
                .flatMap(Set::stream)
                .filter(s -> s.getType().equals("TrustManagerFactory"))
                .map(s -> {
                    try {
                        return TrustManagerFactory.getInstance(s.getAlgorithm(), s.getProvider());
                    } catch (NoSuchAlgorithmException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .peek(tmf -> {
                    try {
                        tmf.init((KeyStore) null);
                    } catch (KeyStoreException e) {
                        // ignore
                    }
                })
                .flatMap(tmf -> Arrays.stream(tmf.getTrustManagers()))
                .forEach(tm -> {
                    var newTm = OmniX509ExtendedTrustManager.wrap(tm, notifier, settings);
                    assertInstanceOf(OmniX509ExtendedTrustManager.class, newTm);
                });
    }
}

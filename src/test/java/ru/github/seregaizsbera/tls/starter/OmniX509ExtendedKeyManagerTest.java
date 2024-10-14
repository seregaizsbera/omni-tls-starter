package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OmniX509ExtendedKeyManagerTest {
    private static final X500Name[] X_500_NAME_ARRAY = new X500Name[1];
    private static final String KEY_TYPE = "keyType";
    private static final String ALIAS = "alias";

    @Mock
    private X509CertImpl implCert;
    @Mock
    private X509ExtendedKeyManager keyManager;
    @Mock
    private OmniSecurityNotifier notifier;
    @Spy
    private OmniTlsStarterSettings settings = new OmniTlsStarterSettings();
    @InjectMocks
    private OmniX509ExtendedKeyManager manager;

    @Test
    void getClientAliases() {
        manager.getClientAliases(KEY_TYPE, X_500_NAME_ARRAY);
        verify(keyManager, times(1)).getClientAliases(eq("keyType"), any());
    }

    @Test
    void chooseClientAlias() {
        manager.chooseClientAlias(new String[]{KEY_TYPE}, X_500_NAME_ARRAY, new Socket());

        verify(keyManager, times(1)).chooseClientAlias(eq(new String[]{"keyType"}), any(), any());
    }

    @Test
    void getServerAliases() {
        manager.getServerAliases(KEY_TYPE, X_500_NAME_ARRAY);

        verify(keyManager, times(1)).getServerAliases(eq("keyType"), any());
    }

    @Test
    void chooseServerAlias() {
        manager.chooseServerAlias(KEY_TYPE, X_500_NAME_ARRAY, new Socket());

        verify(keyManager, times(1)).chooseServerAlias(eq("keyType"), any(), any());
    }

    @Test
    void getCertificateChain_full() {
        when(keyManager.getCertificateChain(any())).thenReturn(new X509CertImpl[]{new X509CertImpl()});
        when(notifier.isFull()).thenReturn(true);

        X509Certificate[] aliases = manager.getCertificateChain("alias");
        assertEquals(1, aliases.length);
        verify(notifier, times(0)).notify(any(OmniX509EventModel.class));
    }

    @Test
    void getCertificateChain_notFull_and_alert() throws CertificateException {
        when(implCert.getNotAfter()).thenReturn(Date.from(Instant.now()));
        when(implCert.getSubjectX500Principal()).thenReturn(TestData.getInstance().realCert.getSubjectX500Principal());
        when(implCert.getSerialNumber()).thenReturn(BigInteger.ZERO);
        when(keyManager.getCertificateChain(any())).thenReturn(new X509CertImpl[]{implCert});
        when(notifier.isFull()).thenReturn(false);

        X509Certificate[] aliases = manager.getCertificateChain(ALIAS);
        assertEquals(1, aliases.length);

        verify(notifier, times(1)).notify(any(OmniX509EventModel.class));
    }

    @Test
    void getCertificateChain_notFull_and_notAlert() {
        when(implCert.getNotAfter()).thenReturn(Date.from(Instant.now().plus(100L, ChronoUnit.DAYS)));

        when(keyManager.getCertificateChain(any())).thenReturn(new X509CertImpl[]{implCert});
        when(notifier.isFull()).thenReturn(false);

        X509Certificate[] aliases = manager.getCertificateChain(ALIAS);
        assertEquals(1, aliases.length);

        verify(notifier, times(0)).notify(any(OmniX509EventModel.class));
    }

    @Test
    void getPrivateKey() {
        manager.getPrivateKey(ALIAS);
        verify(keyManager, times(1)).getPrivateKey("alias");
    }

    @Test
    void wrap() {
        var newKeyManager = OmniX509ExtendedKeyManager.wrap(keyManager, notifier, settings);
        assertInstanceOf(OmniX509ExtendedKeyManager.class, newKeyManager);
    }

    @Test
    void wrapAll() {
        Arrays.stream(Security.getProviders())
                .map(Provider::getServices)
                .flatMap(Set::stream)
                .filter(s -> s.getType().equals("KeyManagerFactory"))
                .map(s -> {
                    try {
                        return KeyManagerFactory.getInstance(s.getAlgorithm(), s.getProvider());
                    } catch (NoSuchAlgorithmException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .peek(kmf -> {
                    try {
                        kmf.init(null, null);
                    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                        // ignore
                    }
                })
                .flatMap(kmf -> Arrays.stream(kmf.getKeyManagers()))
                .forEach(km -> {
                    var newKm = OmniX509ExtendedKeyManager.wrap(km, notifier, settings);
                    assertInstanceOf(OmniX509ExtendedKeyManager.class, newKm);
                });
    }
}

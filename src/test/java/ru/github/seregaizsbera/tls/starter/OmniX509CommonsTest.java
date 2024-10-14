package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;
import sun.security.x509.X509CertImpl;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OmniX509CommonsTest {
    private final OmniTlsStarterSettings config = OmniTlsStarterSettings.getInstance();
    @Captor
    private ArgumentCaptor<OmniX509EventModel> argumentCaptor;
    @Mock
    private OmniSecurityNotifier notifier;
    @Mock
    private X509CertImpl mockCert;

    private X500Principal principal;

    @BeforeEach
    public void init() throws CertificateException {
            principal = TestData.getInstance().realCert.getSubjectX500Principal();
    }
    @Test
    @DisplayName("Проверка сертификата у которого срок использования ниже уровня INFO")
    void getLevelInfo_validCertTest() {
        when(mockCert.getNotAfter()).thenReturn(Date.from(Instant.now().plus(55, ChronoUnit.DAYS)));
        when(mockCert.getSubjectX500Principal()).thenReturn(principal);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.ZERO);
        OmniX509Commons.validateExpiration("type", new X509CertImpl[]{mockCert}, config, notifier, "");
        verify(notifier).notify(argumentCaptor.capture());
        Assertions.assertEquals(Level.INFO, argumentCaptor.getValue().getLevel());
        Assertions.assertNotEquals(Level.WARN, argumentCaptor.getValue().getLevel());
        verify(notifier, times(1)).notify(any(OmniX509EventModel.class));
    }

    @Test
    @DisplayName("Проверка сертификата у которого срок использования ниже уровня WARNING")
    void getLevelWarn_validCertTest() {
        when(mockCert.getNotAfter()).thenReturn(Date.from(Instant.now().plus(20, ChronoUnit.DAYS)));
        when(mockCert.getSubjectX500Principal()).thenReturn(principal);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.ZERO);
        OmniX509Commons.validateExpiration("type", new X509CertImpl[]{mockCert}, config, notifier, "");
        verify(notifier).notify(argumentCaptor.capture());
        Assertions.assertEquals(Level.WARN, argumentCaptor.getValue().getLevel());
        Assertions.assertNotEquals(Level.INFO, argumentCaptor.getValue().getLevel());
        verify(notifier, times(1)).notify(any(OmniX509EventModel.class));
    }

    @Test
    @DisplayName("Проверка сертификата у которого срок использования ниже уровня ERROR")
    void getLevelError_validCertTest() {
        when(mockCert.getNotAfter()).thenReturn(Date.from(Instant.now().plus(5, ChronoUnit.DAYS)));
        when(mockCert.getSubjectX500Principal()).thenReturn(principal);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.ZERO);
        OmniX509Commons.validateExpiration("type", new X509CertImpl[]{mockCert}, config, notifier, "1.2.3.4:1234");
        verify(notifier).notify(argumentCaptor.capture());
        Assertions.assertEquals(Level.ERROR, argumentCaptor.getValue().getLevel());
        Assertions.assertNotEquals(Level.INFO, argumentCaptor.getValue().getLevel());
        verify(notifier, times(1)).notify(any(OmniX509EventModel.class));
    }

    @Test
    @SuppressWarnings("SpellCheckingInspection")
    void extractSAN() throws CertificateException {
        var result = OmniX509Commons.extractSAN(TestData.getInstance().realCert);
        Assertions.assertEquals(" (*.askubuntu.com,*.blogoverflow.com,*.mathoverflow.net...)", result);
    }
}

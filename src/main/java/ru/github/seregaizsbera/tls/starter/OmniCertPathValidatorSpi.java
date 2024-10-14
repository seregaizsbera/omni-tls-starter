package ru.github.seregaizsbera.tls.starter;

import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Реализация менеджера ключей в провайдере безопасности {@value OmniSecurityProvider#NAME}. Делегирует вызовы методов
 * провайдеру безопасности {@value #INTERNAL_PROVIDER}, используя при этом алгоритм {@linkplain #ALGORITHM}.
 */
public class OmniCertPathValidatorSpi extends CertPathValidatorSpi {
    /**
     * Имя провайдера безопасности, которому делегируется выполнение основной работы
     */
    public static final String INTERNAL_PROVIDER = "SUN";
    /**
     * Имя алгоритма, который реализуется в данном классе
     */
    public static final String ALGORITHM = "PKIX";
    private final Provider internalProvider;
    private final OmniSecurityNotifier notifier;

    /**
     * Создает экземпляр объекта.
     */
    public OmniCertPathValidatorSpi() {
        this.internalProvider = Objects.requireNonNull(Security.getProvider(INTERNAL_PROVIDER), "Не найден провайдер безопасности " + INTERNAL_PROVIDER);
        this.notifier = OmniSecurityNotifier.getInstance();
    }

    @SuppressWarnings("java:S1066")
    @Override
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException {
        try {
            var cpv = CertPathValidator.getInstance(ALGORITHM, internalProvider);
            var result = cpv.validate(certPath, params);
            if (result instanceof PKIXCertPathValidatorResult pkixcpvr) {
                var anchor = pkixcpvr.getTrustAnchor().getTrustedCert();
                if (!anchor.getSubjectX500Principal().equals(anchor.getIssuerX500Principal())) {
                    OmniTLSContext.pull().ifPresent(info -> {
                        if (certPath.getCertificates().get(0) instanceof X509Certificate cert0) {
                            if (certPath.getCertificates().size() == info.chainLength()) {
                                var msg = makeIncompleteChainMessage(info, cert0);
                                notifier.notify(new OmniX509EventModel(Level.ERROR, msg, cert0.getSerialNumber().toString(16)));
                            }
                        }
                    });
                }
            }
            return result;
        } catch (GeneralSecurityException e) {
            var exception = new CertPathValidatorException(e);
            exception.setStackTrace(e.getStackTrace());
            throw exception;
        }
    }

    private static String makeIncompleteChainMessage(OmniTLSContext.Data info, X509Certificate cert0) {
        var connectionInfo = info.connInfo();
        var format = "Цепочка сертификатов, начинающаяся с сертификата %1$s%2$s, неполная," +
                " т. е. в ней присутствуют не все промежуточные сертификаты." +
                " Сервер нарушает RFC 5246, раздел 7.4.2, и RFC 8446, раздел 4.4.2";
        if (!connectionInfo.isEmpty()) {
            format += "%n Соединение: %3$s";
        }
        format += " (%4$s).%n";
        return String.format(format, cert0.getSubjectX500Principal().getName(), OmniX509Commons.extractSAN(cert0), connectionInfo, "dqlg");
    }
}

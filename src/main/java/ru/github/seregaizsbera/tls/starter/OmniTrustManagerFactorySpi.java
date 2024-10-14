package ru.github.seregaizsbera.tls.starter;

import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Реализация менеджера доверия в провайдере безопасности {@value OmniSecurityProvider#NAME}. Делегирует вызовы методов
 * провайдеру безопасности {@value #INTERNAL_PROVIDER}, используя при этом алгоритм {@linkplain #ALGORITHM}.
 */
public class OmniTrustManagerFactorySpi extends TrustManagerFactorySpi {
    public static final String INTERNAL_PROVIDER = "SunJSSE";
    private static final String ALGORITHM = TrustManagerFactory.getDefaultAlgorithm();
    private final AtomicReference<TrustManagerFactory> tmf = new AtomicReference<>();
    private final OmniSecurityNotifier notifier;
    private final OmniTlsStarterSettings settings;
    private static final Map<String, String> nonRootCertsToIgnore;
    static {
        nonRootCertsToIgnore = Map.of("CN=Russian Trusted Sub CA,O=The Ministry of Digital Development and Communications,C=RU", "CN=Russian Trusted Root CA,O=The Ministry of Digital Development and Communications,C=RU");
    }

    /**
     * Создает экземпляр объекта.
     */
    public OmniTrustManagerFactorySpi() {
        notifier = OmniSecurityNotifier.getInstance();
        settings = OmniTlsStarterSettings.getInstance();
    }

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        try {
            init(it -> it.init(ks));
        } catch (GeneralSecurityException e) {
            KeyStoreException exception = new KeyStoreException(e);
            exception.setStackTrace(e.getStackTrace());
            throw exception;
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        try {
            init(it -> it.init(spec));
        } catch (GeneralSecurityException e) {
            InvalidAlgorithmParameterException exception = new InvalidAlgorithmParameterException(e);
            exception.setStackTrace(e.getStackTrace());
            throw exception;
        }
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        TrustManagerFactory trustManagerFactory = tmf.get();
        if (trustManagerFactory == null) {
            throw new IllegalStateException(
                    String.format("%s: engine is not initialized", OmniTrustManagerFactorySpi.class.getSimpleName()));
        }
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        Arrays.setAll(trustManagers, i -> OmniX509ExtendedTrustManager.wrap(trustManagers[i], notifier, settings));
        return trustManagers;
    }

    private void init(TMFConsumer tmfConsumer) throws GeneralSecurityException {
        if (tmf.get() != null) {
            throw new IllegalStateException(
                    String.format("%s: engine already initialized", OmniTrustManagerFactorySpi.class.getSimpleName()));
        }
        var result = TrustManagerFactory.getInstance(ALGORITHM, INTERNAL_PROVIDER);
        tmfConsumer.call(result);
        if (!tmf.compareAndSet(null, result)) {
            throw new IllegalStateException(
                    String.format("%s: engine already initialized", OmniTrustManagerFactorySpi.class.getSimpleName()));
        }
        checkForNonRootCA(result);
    }

    private void checkForNonRootCA(TrustManagerFactory result) {
        for (var tm: result.getTrustManagers()) {
            if (tm instanceof X509TrustManager trustManager) {
                Arrays.stream(trustManager.getAcceptedIssuers())
                        .filter(it -> !it.getIssuerX500Principal().equals(it.getSubjectX500Principal()))
                        .filter(it -> !Objects.equals(it.getIssuerX500Principal().getName(), nonRootCertsToIgnore.get(it.getSubjectX500Principal().getName())))
                        .forEach(cert -> {
                            var msg = String.format(Locale.ROOT, "Среди доверенных сертификатов находится несамоподписанный сертификат издателя %s, выданный %s. Такая конфигурация не рекомендуется в промышленной эксплуатации. (%s)",
                                    cert.getSubjectX500Principal().getName(),
                                    cert.getIssuerX500Principal().getName(),
                                    "fnck");
                            notifier.notify(new OmniX509EventModel(Level.WARN, msg, cert.getSerialNumber().toString(16)));
                        });
            }
        }
    }

    private interface TMFConsumer {
        void call(TrustManagerFactory tmf) throws GeneralSecurityException;
    }
}

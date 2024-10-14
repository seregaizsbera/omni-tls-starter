package ru.github.seregaizsbera.tls.starter;

import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

/**
 * Реализация менеджера ключей в провайдере безопасности {@value OmniSecurityProvider#NAME}. Делегирует вызовы методов
 * провайдеру безопасности {@value #INTERNAL_PROVIDER}, используя при этом алгоритм {@linkplain #ALGORITHM}.
 */
public class OmniKeyManagerFactorySpi extends KeyManagerFactorySpi {
    /**
     * Имя провайдера безопасности, которому делегируется выполнение основной работы
     */
    public static final String INTERNAL_PROVIDER = "SunJSSE";
    private static final String ALGORITHM = KeyManagerFactory.getDefaultAlgorithm();
    private final AtomicReference<KeyManagerFactory> kmf = new AtomicReference<>();
    private final OmniSecurityNotifier notifier;
    private final OmniTlsStarterSettings settings;

    /**
     * Создает экземпляр объекта.
     */
    public OmniKeyManagerFactorySpi() {
        this.notifier = OmniSecurityNotifier.getInstance();
        this.settings = OmniTlsStarterSettings.getInstance();
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException {
        try {
            init(it -> it.init(ks, password));
        } catch (GeneralSecurityException e) {
            var exception = new KeyStoreException(e);
            exception.setStackTrace(e.getStackTrace());
            throw exception;
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        try {
            init(it -> it.init(spec));
        } catch (GeneralSecurityException e) {
            var exception = new InvalidAlgorithmParameterException(e);
            exception.setStackTrace(e.getStackTrace());
            throw exception;
        }
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        var keyManagerFactory = kmf.get();
        if (keyManagerFactory == null) {
            throw new IllegalStateException(String.format("%s: engine is not initialized", OmniKeyManagerFactorySpi.class.getSimpleName()));
        }
        var keyManagers = keyManagerFactory.getKeyManagers();
        IntStream.range(0, keyManagers.length)
                .forEach(i -> keyManagers[i] = OmniX509ExtendedKeyManager.wrap(keyManagers[i], notifier, settings));
        return keyManagers;
    }

    private void init(KMFConsumer kmfConsumer) throws GeneralSecurityException {
        if (kmf.get() != null) {
            throw new IllegalStateException(String.format("%s: engine already initialized", OmniKeyManagerFactorySpi.class.getSimpleName()));
        }
        var result = KeyManagerFactory.getInstance(ALGORITHM, INTERNAL_PROVIDER);
        kmfConsumer.call(result);
        if (!kmf.compareAndSet(null, result)) {
            throw new IllegalStateException(String.format("%s: engine already initialized", OmniKeyManagerFactorySpi.class.getSimpleName()));
        }
    }

    private interface KMFConsumer {
        void call(KeyManagerFactory kmf) throws GeneralSecurityException;
    }
}

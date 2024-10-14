package ru.github.seregaizsbera.tls.starter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.Serial;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Провайдер безопасности для Омниканальной платформы. Добавляет дополнительные проверки сертификатов сервера и клиента
 * к стандартным провайдерам.
 * <p>
 * Чтобы провайдер правильно работал, его необходимо добавить в начало списка провайдеров с помощью
 * <pre>
 * {@code Security.insertProviderAt(OmniSecurityProvider.getInstance(), 1)}
 * </pre>
 * <p>
 * Проверить правильность установки провайдера можно с помощью {@link #isCustomManagersSet(boolean)}.
 */
public class OmniSecurityProvider extends Provider {
    @Serial
    private static final long serialVersionUID = 169049587169638339L;
    private static final Logger LOGGER = LoggerFactory.getLogger(OmniSecurityProvider.class);
    private static final Supplier<OmniSecurityProvider> create = OmniSecurityProvider::create;
    private static Supplier<OmniSecurityProvider> accessor = create;
    private static final Map<String, Map<String, String>> implementations;
    private static final Set<String> internalProviders;

    static {
        implementations = Map.of(
                OmniTrustManagerFactorySpi.class.getName(), Map.of(OmniTrustManagerFactorySpi.INTERNAL_PROVIDER, "TrustManagerFactory"),
                OmniKeyManagerFactorySpi.class.getName(), Map.of(OmniKeyManagerFactorySpi.INTERNAL_PROVIDER, "KeyManagerFactory"),
                OmniCertPathValidatorSpi.class.getName(), Map.of(OmniCertPathValidatorSpi.INTERNAL_PROVIDER, "CertPathValidator")
        );
        internalProviders = implementations.values()
                .stream()
                .map(Map::keySet)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    /**
     * Имя, под которым данный провайдер регистрируется в {@linkplain Security}.
     */
    public static final String NAME = "Omni";

    private static OmniSecurityProvider create() {
        synchronized (create) {
            if (accessor != create) {
                return accessor.get();
            }
            OmniSecurityProvider result = new OmniSecurityProvider(NAME);
            result.init();
            accessor = () -> result;
            return result;
        }
    }

    /**
     * Возвращает экземпляр провайдера безопасности.
     *
     * @return экземпляр провайдера безопасности
     */
    public static Provider getInstance() {
        return accessor.get();
    }

    private OmniSecurityProvider(String name) {
        super(name, "1.0", "Провайдер безопасности для TLS в Омниканальной платформе");
    }

    private void init() {
        Consumer<Service> print =
                it -> LOGGER.debug("DEBUG: {}.{}.{} -> {}", it.getProvider().getName(), it.getType(), it.getAlgorithm(), it.getClassName());
        implementations.forEach((implementaion, details) -> {
            LOGGER.warn("{}", implementaion);
            details.forEach((providerName, type) -> Optional.of(providerName)
                    .map(Security::getProvider)
                    .orElseThrow(() -> new IllegalStateException(String.format(Locale.ROOT, "Не найден провайдер безопасности %s", providerName)))
                    .getServices()
                    .stream()
                    .filter(it -> it.getType().equals(type))
                    .peek(print)
                    .map(it -> new Service(this, it.getType(), it.getAlgorithm(), implementaion, null, null))
                    .forEach(this::putService));
        });
    }

    /**
     * Регистрирует провайдера безопасности 1-м в списке, чтобы он имел приоритет над другими уже установленными
     * провайдерами безопасности.
     * <p>
     * В случае ошибки выбрасывает {@linkplain IllegalStateException}.
     */
    public static void registerOnTop() {
        Provider[] providerArray = Security.getProviders();
        int targetPos = 1;

        if (providerArray != null && providerArray[targetPos - 1].equals(getInstance())) {
            return;
        }

        int pos = Security.insertProviderAt(getInstance(), targetPos);
        if (pos != targetPos) {
            String msg = String.format(Locale.ROOT, "Не удалось зарегистрировать провайдер безопасности %s в позиции %d",
                    OmniSecurityProvider.class.getSimpleName(), targetPos);
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Регистрирует провайдера безопасности в конце списка провайдеров. Поскольку он реализует только те алгоритмы,
     * которые доступны в других провайдерах, получить его можно только через явное указание имени {@value #NAME}.
     */
    @SuppressWarnings("unused")
    public static void register() {
        Security.addProvider(getInstance());
    }

    /**
     * Проверка правильности установки провайдера.
     */
    @SuppressWarnings("LoggingSimilarMessage")
    public static boolean isCustomManagersSet(boolean expected) {
        var index = new HashMap<String, Integer>();
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            index.put(providers[i].getName(), i);
        }
        int errors = 0;
        int internal = Integer.MAX_VALUE;
        for (var provider: internalProviders) {
            var pos = index.get(provider);
            if (pos == null) {
                LOGGER.warn("Не найден провайдер безопасности {} ({})", provider, "yfzn");
                errors++;
            } else {
                internal = Math.min(internal, pos);
            }
        }
        if (errors > 0) {
            return false;
        }
        var myPos = index.get(NAME);
        if (myPos == null) {
            if (expected) {
                LOGGER.warn("Не найден провайдер безопасности {} ({})", NAME, "snjp");
            } else {
                LOGGER.debug("Не найден провайдер безопасности {} ({})", NAME, "qrqy");
            }
            return false;
        }
        if (myPos >= internal) {
            LOGGER.warn("Провайдер безопасности {} имеет меньший приоритет, чем {}. Проверьте настройку модуля omni-tls-starter. ({})", NAME, providers[internal].getName(), "jaxb");
            return false;
        }
        return checkTrustManagerFactory() && checkKeyManagerFactory() && checkCertPathValidator();
    }

    private static boolean checkTrustManagerFactory() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            String providerName = tmf.getProvider().getName();
            if (!NAME.equals(providerName)) {
                LOGGER.warn("Провайдер фабрики менеджеров доверия {} вместо {}. Проверьте настройку модуля omni-tls-starter. ({})", providerName, NAME, "edsz");
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn(e.getMessage());
        }
        return true;
    }

    private static boolean checkKeyManagerFactory() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            String providerName = kmf.getProvider().getName();
            if (!NAME.equals(providerName)) {
                LOGGER.warn("Провайдер фабрики менеджеров ключей {} вместо {}. Проверьте настройку модуля omni-tls-starter. ({})", providerName, NAME, "eorr");
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn(e.getMessage());
        }
        return true;
    }

    private static boolean checkCertPathValidator() {
        try {
            var cpv = CertPathValidator.getInstance(OmniCertPathValidatorSpi.ALGORITHM);
            var providerName = cpv.getProvider().getName();
            if (!NAME.equals(providerName)) {
                LOGGER.warn("Провайдер валидатора цепочки сертификатов {} вместо {}. Проверьте настройку модуля omni-tls-starter. ({})", providerName, NAME, "aujj");
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn(e.getMessage());
        }
        return true;
    }
}

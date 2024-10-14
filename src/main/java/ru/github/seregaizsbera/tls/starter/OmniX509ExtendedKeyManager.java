package ru.github.seregaizsbera.tls.starter;

import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Менеджер ключей осуществляет дополнительные проверки сертификатов, которые предоставляет стандартный
 * менеджер ключей {@linkplain X509ExtendedKeyManager}. Результаты проверок отправляются в {@link OmniSecurityNotifier},
 */
class OmniX509ExtendedKeyManager extends X509ExtendedKeyManager {
    private final X509ExtendedKeyManager keyManager;
    private final OmniSecurityNotifier notifier;
    private final OmniTlsStarterSettings settings;

    private OmniX509ExtendedKeyManager(X509ExtendedKeyManager keyManager, OmniSecurityNotifier notifier, OmniTlsStarterSettings settings) {
        this.keyManager = keyManager;
        this.notifier = notifier;
        this.settings = settings;
    }

    /**
     * Создает обертку над стандартным менеджером ключей {@linkplain X509ExtendedKeyManager}. Если менеджер ключей уже обернут
     * или не является экземпляром {@linkplain X509ExtendedKeyManager}, то возвращает исходный объект без обертки.
     *
     * @param keyManager менеджер ключей, который необходимо обернуть
     * @param notifier   объект, в который будут передаваться ошибки проверок
     * @return обертку над менеджером ключей или исходный {@linkplain #keyManager}.
     */
    static KeyManager wrap(KeyManager keyManager, OmniSecurityNotifier notifier, OmniTlsStarterSettings settings) {
        if (keyManager instanceof OmniX509ExtendedKeyManager) {
            return keyManager;
        }
        if (keyManager instanceof X509ExtendedKeyManager x509ExtendedKeyManager) {
            return new OmniX509ExtendedKeyManager(x509ExtendedKeyManager, notifier, settings);
        }
        if (keyManager instanceof X509KeyManager x509KeyManager) {
            var x509ExtendedKeyManager = new X509ExtendedKeyManager() {
                @Override
                public String[] getClientAliases(String keyType, Principal[] issuers) {
                    return x509KeyManager.getClientAliases(keyType, issuers);
                }

                @Override
                public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                    return x509KeyManager.chooseClientAlias(keyType, issuers, socket);
                }

                @Override
                public String[] getServerAliases(String keyType, Principal[] issuers) {
                    return x509KeyManager.getServerAliases(keyType, issuers);
                }

                @Override
                public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                    return x509KeyManager.chooseServerAlias(keyType, issuers, socket);
                }

                @Override
                public X509Certificate[] getCertificateChain(String alias) {
                    return x509KeyManager.getCertificateChain(alias);
                }

                @Override
                public PrivateKey getPrivateKey(String alias) {
                    return x509KeyManager.getPrivateKey(alias);
                }

                @Override
                public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
                    return x509KeyManager.chooseClientAlias(keyType, issuers, null);
                }

                @Override
                public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
                    return x509KeyManager.chooseServerAlias(keyType, issuers, null);
                }
            };
            return new OmniX509ExtendedKeyManager(x509ExtendedKeyManager, notifier, settings);
        }
        return keyManager;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return keyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return keyManager.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return keyManager.chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return keyManager.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return keyManager.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return keyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] chain = keyManager.getCertificateChain(alias);
        if (!notifier.isFull()) {
            OmniX509Commons.validateExpiration("KeyManager", chain, settings, notifier, "");
        }
        return chain;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return keyManager.getPrivateKey(alias);
    }
}

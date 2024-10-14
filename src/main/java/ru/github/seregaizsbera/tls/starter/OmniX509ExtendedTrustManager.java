package ru.github.seregaizsbera.tls.starter;

import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Optional;

/**
 * Менеджер доверия осуществляет дополнительные проверки сертификатов, которые предоставляет стандартный
 * менеджер доверия {@linkplain X509ExtendedTrustManager}. Результаты проверок отправляются в {@link OmniSecurityNotifier},
 */
class OmniX509ExtendedTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager trustManager;
    private final OmniSecurityNotifier notifier;
    private final OmniTlsStarterSettings settings;
    private final OmniTlsStarterSettings.Mode mode;

    private OmniX509ExtendedTrustManager(X509ExtendedTrustManager trustManager, OmniSecurityNotifier notifier, OmniTlsStarterSettings settings) {
        this.trustManager = trustManager;
        this.notifier = notifier;
        this.settings = settings;
        this.mode = settings.getMode();
    }

    /**
     * Создает обертку над стандартным менеджером доверия {@linkplain X509ExtendedTrustManager}. Если менеджер ключей
     * уже обернут или не является экземпляром {@linkplain X509ExtendedTrustManager}, то возвращает исходный объект
     * без обертки.
     *
     * @param trustManager менеджер доверия, который необходимо обернуть
     * @param notifier     объект, в который будут передаваться ошибки проверок
     *
     * @return обертку над менеджером ключей или исходный {@linkplain #trustManager}.
     */
    static TrustManager wrap(TrustManager trustManager, OmniSecurityNotifier notifier, OmniTlsStarterSettings settings) {
        if (trustManager instanceof OmniX509ExtendedTrustManager) {
            return trustManager;
        }
        if (trustManager instanceof X509ExtendedTrustManager x509ExtendedTrustManager) {
            return new OmniX509ExtendedTrustManager(x509ExtendedTrustManager, notifier, settings);
        }
        if (trustManager instanceof X509TrustManager x509TrustManager) {
            var x509ExtendedTrustManager = new X509ExtendedTrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                    x509TrustManager.checkClientTrusted(chain, authType);
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                    x509TrustManager.checkServerTrusted(chain, authType);
                }
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                    x509TrustManager.checkClientTrusted(chain, authType);
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                    x509TrustManager.checkServerTrusted(chain, authType);
                }
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    x509TrustManager.checkClientTrusted(chain, authType);
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    x509TrustManager.checkServerTrusted(chain, authType);
                }
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return x509TrustManager.getAcceptedIssuers();
                }
            };
            return new OmniX509ExtendedTrustManager(x509ExtendedTrustManager, notifier, settings);
        }
        return trustManager;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            trustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            throwOrNotify(e, chain, null, null);
        }
        if (!notifier.isFull()) {
            performServerValidations(chain, null, null);
        }
    }

    private void throwOrNotify(CertificateException e, X509Certificate[] chain, Socket socket, SSLEngine engine) throws CertificateException {
        if (mode.bypass(e)) {
            var connInfo = getConnectionInfo(socket, engine);
            var connPrefix = connInfo.isEmpty() ? "" : " ";
            var cert = chain[0];
            notifier.notify(new OmniX509EventModel(Level.ERROR, e.getMessage() + " " + cert.getSubjectX500Principal().getName() + connPrefix + connInfo, cert.getSerialNumber().toString(16)));
        } else {
            throw e;
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        try {
            trustManager.checkServerTrusted(chain, authType, socket);
        } catch (CertificateException e) {
            throwOrNotify(e, chain, socket, null);
        }
        if (!notifier.isFull()) {
            performServerValidations(chain, socket, null);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        try {
            trustManager.checkServerTrusted(chain, authType, engine);
        } catch (CertificateException e) {
            throwOrNotify(e, chain, null, engine);
        }
        if (!notifier.isFull()) {
            performServerValidations(chain, null, engine);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
        if (!notifier.isFull()) {
            performClientValidations(chain, null, null);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType, socket);
        if (!notifier.isFull()) {
            performClientValidations(chain, socket, null);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType, engine);
        if (!notifier.isFull()) {
            performClientValidations(chain, null, engine);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }

    private void performServerValidations(X509Certificate[] chain, Socket socket, SSLEngine engine) {
        String connectionInfo = getConnectionInfo(socket, engine);
        OmniX509Commons.validateExpiration("Серверный", chain, settings, notifier, connectionInfo);
        OmniTLSContext.push(connectionInfo, chain.length);
    }

    private static String getConnectionInfo(Socket socket, SSLEngine engine) {
        var socketInfo = Optional.ofNullable(socket)
                .map(s -> String.format(Locale.ROOT, "%s:%d:%s:%d", s.getLocalAddress().getHostAddress(),
                        s.getLocalPort(), s.getInetAddress().getHostAddress(), s.getPort()))
                .orElse("");
        var engineInfo = Optional.ofNullable(engine)
                .map(s -> String.format(Locale.ROOT, "%s:%d", s.getPeerHost(), s.getPeerPort()))
                .orElse("");
        return socketInfo + engineInfo;
    }

    private void performClientValidations(X509Certificate[] chain, Socket socket, SSLEngine engine) {
        var connectionInfo = getConnectionInfo(socket, engine);
        OmniX509Commons.validateExpiration("Клиентский", chain, settings, notifier, connectionInfo);
    }
}

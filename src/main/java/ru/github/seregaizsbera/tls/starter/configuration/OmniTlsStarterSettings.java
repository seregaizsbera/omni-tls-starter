package ru.github.seregaizsbera.tls.starter.configuration;

import org.slf4j.event.Level;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;

@Configuration
@ConfigurationProperties(prefix = "omni-tls.certificate")
public class OmniTlsStarterSettings {
    private static OmniTlsStarterSettings instance = null;

    @SuppressWarnings("java:S2696")
    public static OmniTlsStarterSettings getInstance() {
        if (instance == null) {
            instance = new OmniTlsStarterSettings();
        }
        return instance;
    }

    /**
     * Количество дней до истечения периода действия сертификата, после которого будет выводиться предупреждение.
     */
    private long infoLevelDays = 90;
    private long warningLevelDays = 30;
    private long errorLevelDays = 7;
    private Mode mode = Mode.STRICT;

    @PostConstruct
    @SuppressWarnings("java:S2696")
    private void storeGlobally() {
        instance = this;
    }

    public long getInfoLevelDays() {
        return infoLevelDays;
    }

    public void setInfoLevelDays(long infoLevelDays) {
        this.infoLevelDays = infoLevelDays;
    }

    public long getWarningLevelDays() {
        return warningLevelDays;
    }

    public void setWarningLevelDays(long warningLevelDays) {
        this.warningLevelDays = warningLevelDays;
    }

    public long getErrorLevelDays() {
        return errorLevelDays;
    }

    public void setErrorLevelDays(long errorLevelDays) {
        this.errorLevelDays = errorLevelDays;
    }

    public boolean isBelowExpirationThreshold(long days) {
        return days < infoLevelDays;
    }

    public Level getLevel(long days) {
        if (days < getErrorLevelDays()) {
            return Level.ERROR;
        } else if (days < getWarningLevelDays()) {
            return Level.WARN;
        } else {
            return Level.INFO;
        }
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public enum Mode {
        /**
         * Стандартный режим. При любой ошибке соединение отклоняется.
         */
        STRICT((new CertificateException() {}).getClass()),
        /**
         * Допускается подключение с истекшим сертификатом.
         */
        ALLOW_EXPIRED(CertificateExpiredException.class),
        /**
         * Допускается любое подключение, независимо от наличия ошибок.
         */
        INSECURE(CertificateException.class);

        private final Class<? extends CertificateException> whatToBypass;

        Mode(Class<? extends CertificateException> whatToBypass) {
            this.whatToBypass = whatToBypass;
        }

        public boolean bypass(CertificateException e) {
            return whatToBypass.isInstance(e);
        }
    }
}

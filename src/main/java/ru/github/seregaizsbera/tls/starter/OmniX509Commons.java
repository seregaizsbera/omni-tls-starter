package ru.github.seregaizsbera.tls.starter;

import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Общие методы для классов, используемых в {@link OmniSecurityProvider}.
 */
final class OmniX509Commons {
    private OmniX509Commons() {
    }

    /**
     * Проверка сертификатов на время действия. Если сертификат истекает менее, чем через thresholdDays дней,
     * то отдает предупреждение в notifier.
     *
     * @param type           тип сертификата
     * @param chain          цепочка сертификатов
     * @param settings       Настройки периода срабатывания
     * @param notifier       логгер, в который передать сообщения
     * @param connectionInfo информация о TCP-соединении для диагностики
     */
    static void validateExpiration(String type, X509Certificate[] chain, OmniTlsStarterSettings settings,
                                   OmniSecurityNotifier notifier, String connectionInfo) {
        String connInfo = Objects.requireNonNullElse(connectionInfo, "");
        for (X509Certificate cert: chain) {
            long days = Duration.between(Instant.now(), cert.getNotAfter().toInstant()).toDays();
            if (settings.isBelowExpirationThreshold(days)) {
                String msg = makeMessage(type, connInfo, cert, days);
                notifier.notify(new OmniX509EventModel(settings.getLevel(days), msg, cert.getSerialNumber().toString(16)));
            }
        }
    }

    private static String makeMessage(String type, String connInfo, X509Certificate cert, long days) {
        var principal = cert.getSubjectX500Principal().getName();
        var subject = extractSAN(cert);
        String format = "%1$s %2$s сертификат %3$s";
        long d = days;
        if (days > 0) {
            format += " истекает через %4$d дней (%5$s)";
        } else if (days == 0) {
            format += " истек (%5$s)";
        } else {
            d = -days;
            format += " истек %4$d дней назад (%5$s)";
        }
        if (!connInfo.isEmpty()) {
            format += "%n Соединение: %6$s";
        }
        return String.format(Locale.ROOT, format, type, principal, subject, d, "ghtz", connInfo);
    }

    /**
     * Возвращает список subjectAlternateNames сертификата в виде строки в скобках.
     * Если список пуст, возвращает пустую строку.
     * Если имен много, то берутся несколько первых элементов, и добавляется многоточие.
     *
     * @param cert сертификат
     * @return список имен в виде строки
     */
    static String extractSAN(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return "";
            }
            int maxElements = 3; // используются только первые maxElements имен, чтобы не захламлять лог
            String suffix = sans.size() <= maxElements ? ")" : "...)";
            return sans
                    .stream()
                    .flatMap(Collection::stream)
                    .filter(String.class::isInstance)
                    .limit(maxElements)
                    .map(Object::toString)
                    .collect(Collectors.joining(",", " (", suffix));
        } catch (CertificateParsingException e) {
            // Если не удалось извлечь из сертификата доп. имена, то считается, что их нет
            return "";
        }
    }
}

package ru.github.seregaizsbera.tls.starter.models;

import org.slf4j.event.Level;

/**
 * Содержит данные о событии, подлежащем выводу в лог
 */
public class OmniX509EventModel {
    /**
     * Уровень серьезности события
     */
    private final Level level;
    /**
     * Сообщение о событии
     */
    private final String message;
    /**
     * Идентификатор сертификата, к которому относится данное событие
     */
    private final String certificateIdentifier;
    /**
     * Время события Unixtime millis
     */
    private final long timestamp;

    /**
     * Уровень по умолчанию ERROR
     *
     * @param level уровень серьезности события
     * @param message сообщение о событии
     * @param certificateIdentifier контрольная сумма сертификат, к которому относится событие
     */
    public OmniX509EventModel(Level level, String message, String certificateIdentifier) {
        this.level = level;
        this.message = message;
        this.certificateIdentifier = certificateIdentifier;
        this.timestamp = System.currentTimeMillis();
    }

    public Level getLevel() {
        return level;
    }

    public String getMessage() {
        return message;
    }

    public String getCertificateIdentifier() {
        return certificateIdentifier;
    }

    public long getTimestamp() {
        return timestamp;
    }
}

package ru.github.seregaizsbera.tls.starter;

import java.util.Optional;

/**
 * Данный класс сохраняет данные о валидируемом сеансе для передачи между
 * компонентами {@link OmniX509ExtendedTrustManager} и {@link OmniCertPathValidatorSpi}.
 * Использует ThreadLocal-переменные.
 */
final class OmniTLSContext {
    private static final ThreadLocal<Data> container = new ThreadLocal<>();

    /**
     * Сохраняет информацию о валидируемом сеансе. Предназначен для вызова из
     * класса {@link OmniX509ExtendedTrustManager}. Сохраненные данные затем
     * должны быть извлечены классом {@link OmniCertPathValidatorSpi}.
     *
     * @param connInfo информация о соединении или пустая строка
     * @param chainLength длина полученной с сервера цепочки сертификатов
     */
    static void push(String connInfo, int chainLength) {
        container.set(new Data(connInfo, chainLength));
    }

    /**
     * Возвращает информацию, сохраненную методом {@link #push(String, int)},
     * и удаляет ее. Предназначен для вызова из класса {@link OmniCertPathValidatorSpi}.
     *
     * @return Сохраненная информация
     */
    static Optional<Data> pull() {
        var result = Optional.ofNullable(container.get());
        container.remove();
        return result;
    }

    /**
     * Информация о валидируемом сеансе.
     * @param connInfo информация о сетевом соединении или пустая строка, если информация недоступна
     * @param chainLength длина цепочки сертификатов, полученной с сервера
     */
    record Data(String connInfo, int chainLength) {}
}

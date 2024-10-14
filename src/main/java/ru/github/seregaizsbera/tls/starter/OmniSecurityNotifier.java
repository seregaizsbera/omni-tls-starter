package ru.github.seregaizsbera.tls.starter;

import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

/**
 * Логгер, который реагирует на ошибки в дополнительных проверках {@link OmniSecurityProvider}.
 * <p>
 * Задача данного логгера - не допустить зацикливания вызов объектов безопасности и ограничить количество сообщений.
 */
interface OmniSecurityNotifier {

    /**
     * Логирует событие.
     *
     * @param event событие, которое необходимо залогировать с возможностью изменить уровень логгирования
     *
     * @return true, если событие принято, false, если логгер переполнен
     */
    @SuppressWarnings("UnusedReturnValue")
    boolean notify(OmniX509EventModel event);

    /**
     * Сообщает, переполнен ли логгер. Если логгер переполнен, то новое событие залогировано не будет, и можно не делать
     * проверки, порождающие новые события.
     *
     * @return true, если логгер переполнен
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    boolean isFull();

    /**
     * Возвращает экземпляр логгера.
     *
     * @return экземпляр логгера
     */
    static OmniSecurityNotifier getInstance() {
        try {
            // Провайдер безопасности не должен иметь внешних зависимостей, чтобы не допустить циклических вызовов.
            // Поэтому реализация интерфейса подбирается через рефлексию.
            return (OmniSecurityNotifier) Class.forName("ru.github.seregaizsbera.tls.starter.OmniSecurityNotifierImpl")
                    .getDeclaredMethod("getInstance")
                    .invoke(null);
        } catch (ReflectiveOperationException e) {
            return new OmniSecurityNotifier() {
                @Override
                public boolean notify(OmniX509EventModel event) {
                    return false;
                }

                @Override
                public boolean isFull() {
                    return false;
                }
            };
        }
    }
}

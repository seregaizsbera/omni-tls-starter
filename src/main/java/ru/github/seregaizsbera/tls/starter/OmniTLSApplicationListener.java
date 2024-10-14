package ru.github.seregaizsbera.tls.starter;

import org.springframework.boot.context.event.ApplicationStartingEvent;
import org.springframework.context.ApplicationListener;

/**
 * Загружает провайдера безопасности с нашей реализацией трастменеджером. Запускается
 * на старте приложения Spring Boot.
 */
public class OmniTLSApplicationListener implements ApplicationListener<ApplicationStartingEvent> {
    @Override
    public void onApplicationEvent(ApplicationStartingEvent event) {
        if (!OmniSecurityProvider.isCustomManagersSet(false)) {
            OmniSecurityProvider.registerOnTop();
        }
    }
}

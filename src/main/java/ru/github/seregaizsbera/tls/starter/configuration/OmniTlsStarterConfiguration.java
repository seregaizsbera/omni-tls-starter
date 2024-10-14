package ru.github.seregaizsbera.tls.starter.configuration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import ru.github.seregaizsbera.tls.starter.OmniSecurityProvider;
import ru.github.seregaizsbera.tls.starter.OmniTLSApplicationListener;

import javax.annotation.PostConstruct;

@Order(Ordered.HIGHEST_PRECEDENCE)
@Configuration
@EnableConfigurationProperties(OmniTlsStarterSettings.class)
public class OmniTlsStarterConfiguration {

    /**
     * Установка провайдера безопасности должна делаться, как можно раньше, поэтому
     * по дизайну это делается в {@link OmniTLSApplicationListener}.
     * Здесь дополнительно делается повторная попытка установки, если что-то пошло не так,
     * и провайдер все еще не установлен.
     */
    @PostConstruct
    public void execute() {
        if (!OmniSecurityProvider.isCustomManagersSet(false)) {
            OmniSecurityProvider.registerOnTop();
        }
    }
}

package ru.github.seregaizsbera.tls.starter.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import ru.github.seregaizsbera.tls.starter.configuration.OmniTlsStarterSettings;

@SpringBootApplication
@EnableConfigurationProperties(OmniTlsStarterSettings.class)
public class TestApplication {
    /**
     * Метод запуска главного класса (в действительности не вызывается)
     *
     * @param args аргументы запуска
     */
    public static void main(String[] args) {
        try {
            SpringApplication.run(TestApplication.class, args);
        } catch (Throwable e) {
            System.out.println("Ошибка при старте приложения:");
            e.printStackTrace(System.out);
            throw e;
        }
    }
}

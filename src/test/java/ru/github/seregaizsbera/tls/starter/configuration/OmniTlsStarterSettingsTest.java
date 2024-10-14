package ru.github.seregaizsbera.tls.starter.configuration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import ru.github.seregaizsbera.tls.starter.app.TestApplication;

import org.slf4j.event.Level;

import java.security.cert.CertificateParsingException;

@ActiveProfiles(profiles = "test")
@SpringBootTest(classes = TestApplication.class)
class OmniTlsStarterSettingsTest {

    @Autowired
    private OmniTlsStarterSettings omniTlsStarterSettings;

    @Test
    void getInfoLevelTest() {
        Assertions.assertEquals(150, omniTlsStarterSettings.getInfoLevelDays());
    }

    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @Test
    void setInfoLevelTest() {
        Assertions.assertEquals(150, omniTlsStarterSettings.getInfoLevelDays());
        omniTlsStarterSettings.setInfoLevelDays(100);
        Assertions.assertEquals(100, omniTlsStarterSettings.getInfoLevelDays());
        omniTlsStarterSettings.setMode(OmniTlsStarterSettings.Mode.STRICT);
        Assertions.assertFalse(omniTlsStarterSettings.getMode().bypass(new CertificateParsingException()));
    }

    @Test
    void getWarningLevelTest() {
        Assertions.assertEquals(70, omniTlsStarterSettings.getWarningLevelDays());
    }

    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @Test
    void setWarningLevel() {
        Assertions.assertEquals(70, omniTlsStarterSettings.getWarningLevelDays());
        omniTlsStarterSettings.setWarningLevelDays(80);
        Assertions.assertEquals(80, omniTlsStarterSettings.getWarningLevelDays());
    }

    @Test
    void getErrorLevel() {
        Assertions.assertEquals(2, omniTlsStarterSettings.getErrorLevelDays());
    }

    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @Test
    void setErrorLevel() {
        Assertions.assertEquals(2, omniTlsStarterSettings.getErrorLevelDays());
        omniTlsStarterSettings.setErrorLevelDays(5);
        Assertions.assertEquals(5, omniTlsStarterSettings.getErrorLevelDays());
    }

    @Test
    void getLevel() {
        Assertions.assertEquals(Level.INFO, omniTlsStarterSettings.getLevel(149));
    }
}

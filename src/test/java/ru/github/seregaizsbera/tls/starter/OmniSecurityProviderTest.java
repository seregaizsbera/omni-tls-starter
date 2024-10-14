package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OmniSecurityProviderTest {
    private static final String PROVIDER_NAME = "Omni";
    private static ProviderList providerList;

    @BeforeAll
    public static void setUp(){
        providerList = Providers.getProviderList();
    }

    @AfterAll
    public static void cleanUp(){
        Providers.setProviderList(providerList);
    }

    @Test
    void registerOnTop() {
        assertDoesNotThrow(OmniSecurityProvider::registerOnTop);
        assertEquals(PROVIDER_NAME, Security.getProviders()[0].getName());
    }

    @Test
    void register() {
        OmniSecurityProvider.register();
        assertTrue(Arrays.stream(Security.getProviders()).anyMatch(provider -> provider.getName().contains(PROVIDER_NAME)));
    }

    @Test
    void isCustomManagersSet_false() {
        assertFalse(OmniSecurityProvider.isCustomManagersSet(false));
        Security.removeProvider("SunJSSE");
    }

    @Test
    void isCustomManagersSet_withoutSunProvider() {
        Security.removeProvider("SunJSSE");
        assertFalse(OmniSecurityProvider.isCustomManagersSet(false));
    }

    @Test
    void isCustomManagersSet_falseByPriority() {
        Security.insertProviderAt(OmniSecurityProvider.getInstance(), 10);
        assertFalse(OmniSecurityProvider.isCustomManagersSet(false));
    }
}

package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.context.event.ApplicationStartingEvent;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class OmniTLSApplicationListenerTest {
    @Mock
    private ApplicationStartingEvent event;

    @Test
    void onApplicationEvent() {
        var listener = new OmniTLSApplicationListener();
        listener.onApplicationEvent(event);
        assertTrue(OmniSecurityProvider.isCustomManagersSet(true));
    }
}

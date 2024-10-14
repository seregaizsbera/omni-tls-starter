package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import java.lang.reflect.Field;
import java.util.concurrent.BlockingQueue;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class OmniSecurityNotifierImplTest {

    @AfterEach
    void cleanUp() throws Exception {
        OmniSecurityNotifierImpl instance = OmniSecurityNotifierImpl.getInstance();
        Field field = OmniSecurityNotifierImpl.class.getDeclaredField("events");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        BlockingQueue<OmniX509EventModel> events = (BlockingQueue<OmniX509EventModel>) field.get(instance);
        events.clear();
    }

    @Test
    @DisplayName("Проверка добавления события в очередь и её наполненности после одного добавления")
    void testNotify() {
        OmniSecurityNotifier instance = OmniSecurityNotifierImpl.getInstance();

        OmniX509EventModel mockEvent = Mockito.mock(OmniX509EventModel.class);
        when(mockEvent.getMessage()).thenReturn("Test event");
        when(mockEvent.getLevel()).thenReturn(Level.INFO);

        assertTrue(instance.notify(mockEvent));
        assertFalse(instance.isFull());
    }

    @Test
    @DisplayName("Проверка переполнения очереди после добавления 10 событий")
    void testIsFull() {
        OmniSecurityNotifier instance = OmniSecurityNotifierImpl.getInstance();

        OmniX509EventModel mockEvent = Mockito.mock(OmniX509EventModel.class);
        when(mockEvent.getMessage()).thenReturn("Test event");
        when(mockEvent.getLevel()).thenReturn(Level.INFO);

        for(int i = 0; i < 10; i++) {
            instance.notify(mockEvent);
        }

        assertTrue(instance.isFull());
    }

}

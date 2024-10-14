package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EventLimiterTest {

    @Test
    void accept() {
        var eventLimiter = new EventLimiter(3_600_000L);
        var ts = System.currentTimeMillis();
        assertTrue(eventLimiter.accept("1", "2", ts));
        assertTrue(eventLimiter.accept("1", "3", ts + 30L));
        assertTrue(eventLimiter.accept("1", "4", ts + 40L));
        assertTrue(eventLimiter.accept("1", "5", ts + 50L));
        assertTrue(eventLimiter.accept("2", "2", ts + 60L));
        ts += 1_000_000L;
        assertFalse(eventLimiter.accept("1", "2", ts));
        ts += 1_000_000L;
        assertFalse(eventLimiter.accept("1", "2", ts));
        ts += 1_000_000L;
        assertFalse(eventLimiter.accept("1", "2", ts));
        ts += 1_000_000L;
        assertTrue(eventLimiter.accept("1", "2", ts));
    }
}

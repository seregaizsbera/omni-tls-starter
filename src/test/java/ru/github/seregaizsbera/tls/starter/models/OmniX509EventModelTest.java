package ru.github.seregaizsbera.tls.starter.models;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

class OmniX509EventModelTest {
    private final OmniX509EventModel omniX509EventModel = new OmniX509EventModel(Level.ERROR, "Some message", "0");

    @Test
    void getLevel() {
        Assertions.assertEquals(Level.ERROR, omniX509EventModel.getLevel());
    }

    @Test
    void getMessage() {
        Assertions.assertEquals("Some message", omniX509EventModel.getMessage());
    }
}

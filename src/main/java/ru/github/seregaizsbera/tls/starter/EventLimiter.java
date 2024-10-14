package ru.github.seregaizsbera.tls.starter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Ограничивает число событий, относящихся к одной и той же паре идентификаторов,
 * которые можно обработать за указанный период.
 * Если событие можно обработать, метод {@link #accept(String, String, long)} возвращает <code>true</code>.
 * Рассчитывает на то, что будет использоваться в 1 потоке. Не thread-safe.
 */
class EventLimiter {
    private final Map<String, Map<String, Long>> index1; // key1 -> key2 -> timestamp
    private final SortedMap<Long, Map<String, Set<String>>> index2; // timestamp -> key1 -> key2
    private final long limitPeriodMs;
    private long lastTime = Long.MIN_VALUE;

    /**
     * Конструктор
     *
     * @param limitPeriodMs период, в течение которого не допускается повторение событий
     */
    EventLimiter(long limitPeriodMs) {
        this.limitPeriodMs = limitPeriodMs;
        this.index1 = new HashMap<>();
        this.index2 = new TreeMap<>();
    }

    /**
     * Проверяет, можно ли обработать событие. Запоминает время и ключи для последующих проверок.
     * Удаляет устаревшие данные.
     *
     * @param key1 1-й ключ
     * @param key2 2-й ключ
     * @param timestamp время события
     * @return <code>true</code>, если событие можно обработать
     */
    boolean accept(String key1, String key2, long timestamp) {
        long now = correctCurrentTimestamp(timestamp);
        long last = index1.getOrDefault(key1, Map.of()).getOrDefault(key2, Long.MIN_VALUE);
        if (now < last + limitPeriodMs) {
            // В истории есть событие с теми же ключами, произошедшее недавно. Обработка запрещается.
            return false;
        }
        save(key1, key2, now);
        cleanup(now);
        return true;
    }

    /**
     * Сохранить в истории информацию о событии
     *
     * @param key1 1-й ключ
     * @param key2 2-й ключ
     * @param timestamp время события
     */
    private void save(String key1, String key2, long timestamp) {
        Long timestampBoxed = timestamp;
        var removedTimestamp = index1.computeIfAbsent(key1, k -> new HashMap<>()).put(key2, timestampBoxed);
        index2.computeIfAbsent(timestampBoxed, k -> new HashMap<>()).computeIfAbsent(key1, k -> new HashSet<>()).add(key2);
        if (removedTimestamp != null) {
            // В журнале находилось старое сообщение с указанными ключами.
            // Необходимо удалить информацию о нем.
            var key1ToKeys2 = index2.getOrDefault(removedTimestamp, Map.of());
            var keys2 = key1ToKeys2.getOrDefault(key1, Set.of());
            keys2.remove(key2);
            if (keys2.isEmpty()) {
                key1ToKeys2.remove(key1);
                if (key1ToKeys2.isEmpty()) {
                    index2.remove(removedTimestamp);
                }
            }
        }
    }

    /**
     * Очистить историю устаревших событий.
     *
     * @param timestamp будут удалены все данные, до указанного момента времени
     */
    private void cleanup(long timestamp) {
        // выборка всех событий, которые произошли до текущего минус limitPeriodMs
        var toRemove = index2.headMap(timestamp - limitPeriodMs);
        toRemove.forEach((ts, key1ToKeys2) -> key1ToKeys2.forEach((key1, keys2) -> {
            var keys2ToTs = index1.getOrDefault(key1, Map.of());
            if (!keys2ToTs.isEmpty()) {
                keys2.forEach(keys2ToTs::remove);
            }
            if (keys2ToTs.isEmpty()) {
                index1.remove(key1);
            }
        }));
        toRemove.clear();
    }

    /**
     * Если события пришли не по порядку, то в качестве времени очередного события будет использоваться время наиболее
     * позднего известного события.
     *
     * @param timestamp время события
     * @return timestamp или время наиболее позднего события, если события пришли не по порядку
     */
    private long correctCurrentTimestamp(long timestamp) {
        if (timestamp < lastTime) {
            // Непорядок. Такого быть не должно, но если случится,
            // то не позволим сломать работу данного класса.
            return lastTime;
        }
        this.lastTime = timestamp;
        return timestamp;
    }
}

package ru.github.seregaizsbera.tls.starter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import ru.github.seregaizsbera.tls.starter.models.OmniX509EventModel;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Реализация {@link OmniSecurityNotifier}. Работает через очередь, разбираемую по таймеру.
 */
final class OmniSecurityNotifierImpl implements Runnable, OmniSecurityNotifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(OmniSecurityNotifierImpl.class);
    private static final int CAPACITY = 10;
    private static final long POLL_PERIOD_MS = 60_000L;
    private static final long INITIAL_POLL_DELAY_MS = 10_000L;
    private static final long SPAM_PREVENTION_DELAY_MS = 3_600_000L;
    private static final ReentrantLock lock = new ReentrantLock();
    private static final Supplier<OmniSecurityNotifierImpl> create = OmniSecurityNotifierImpl::create;
    private static Supplier<OmniSecurityNotifierImpl> accessor = create;
    private final BlockingQueue<OmniX509EventModel> events;
    private final EventLimiter eventLimiter;

    private OmniSecurityNotifierImpl() {
        this.events = new ArrayBlockingQueue<>(CAPACITY);
        this.eventLimiter = new EventLimiter(SPAM_PREVENTION_DELAY_MS);
    }

    private static OmniSecurityNotifierImpl create() {
        lock.lock();
        try {
            if (accessor != create) {
                return accessor.get();
            }
            OmniSecurityNotifierImpl result = new OmniSecurityNotifierImpl();
            result.start();
            accessor = () -> result;
            return result;
        } finally {
            lock.unlock();
        }
    }

    private void start() {
        ThreadFactory threadFactory = r -> {
            Thread thread = new Thread(r, OmniSecurityNotifierImpl.class.getSimpleName());
            thread.setDaemon(true);
            return thread;
        };
        Executors.newScheduledThreadPool(1, threadFactory).scheduleAtFixedRate(this, INITIAL_POLL_DELAY_MS, POLL_PERIOD_MS, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean notify(OmniX509EventModel event) {
        return events.offer(event);
    }

    @Override
    public boolean isFull() {
        return events.remainingCapacity() <= 0;
    }

    @SuppressWarnings("CallToPrintStackTrace")
    @Override
    public void run() {
        try {
            int cnt = events.size();
            for (int i = 0; i < cnt && !events.isEmpty(); i++) {
                OmniX509EventModel event = events.poll();
                String eventMessage = event.getMessage();
                String certId = event.getCertificateIdentifier();
                if (!eventLimiter.accept(certId, eventMessage, event.getTimestamp())) {
                    continue;
                }
                Level level = event.getLevel();
                switch (level) {
                    case ERROR:
                        LOGGER.error("{}", eventMessage);
                        break;
                    case WARN:
                        LOGGER.warn("{}", eventMessage);
                        break;
                    case INFO:
                        LOGGER.info("{}", eventMessage);
                        break;
                    case DEBUG:
                        LOGGER.debug("{}", eventMessage);
                        break;
                    case TRACE:
                        LOGGER.trace("{}", eventMessage);
                        break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static OmniSecurityNotifierImpl getInstance() {
        return accessor.get();
    }
}

package com.bugra.filter.filter.login_register.ratelimiter;

import com.bugra.support.concurrency.LoginRateLimiterTestHelper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class LoginRateLimiterConcurrencyTest {

    private final Logger logger = LoggerFactory.getLogger(LoginRateLimiterConcurrencyTest.class);
    private final int LIMIT = 5;

    @Test
    void shouldBeThreadSafe() throws InterruptedException {
        String ip = "192.168.1.1";
        LoginRateLimiterTestHelper limiter = new LoginRateLimiterTestHelper();

        int threadSize = 100;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch downLatch = new CountDownLatch(threadSize);

        ExecutorService pool = Executors.newFixedThreadPool(threadSize);

        AtomicInteger successCount = new AtomicInteger(0);

        for(int i = 0; i< threadSize; i++){
            pool.submit(() -> {
                try {
                    startLatch.await();

                    if(limiter.tryConsume(ip)){
                        successCount.incrementAndGet();
                    }

                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }finally {
                    downLatch.countDown();
                }
            });
        }

        logger.info("All thread are ready to test");
        startLatch.countDown();

        downLatch.await();

        assertEquals(LIMIT, successCount.get());
    }
}

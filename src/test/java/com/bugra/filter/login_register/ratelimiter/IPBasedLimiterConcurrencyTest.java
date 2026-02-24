package com.bugra.filter.login_register.ratelimiter;

import com.bugra.enums.EndPoints;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class IPBasedLimiterConcurrencyTest {

    private final Logger logger = LoggerFactory.getLogger(IPBasedLimiterConcurrencyTest.class);
    private final int LIMIT = 5;

    @Autowired
    MockMvc mvc;

    @Test
    void filterConcurrencyTest() throws Exception {

        String spammer_ip = "192.168.1.1";

        int threadSize = 100;
        ExecutorService executorService = Executors.newFixedThreadPool(threadSize);

        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadSize);
        AtomicInteger requestCounter = new AtomicInteger(0);

        for(int i = 0; i< threadSize; i++){
            executorService.submit(() -> {
                try {
                    startLatch.await();
                    var res = mvc.perform(post(EndPoints.LOGIN.getPath())
                            .header("X-Forwarded-For", spammer_ip))
                            .andExpect(status().is(not(429)))
                            .andReturn();

                    int status = res.getResponse().getStatus();
                    if(status != 429){
                        requestCounter.incrementAndGet();
                    }

                }catch (Exception e) {
                    throw new RuntimeException(e);
                }finally {
                    endLatch.countDown();
                }
            });
        }

        logger.info("All test thread are ready, starting now...");
        startLatch.countDown();

        //Wait for all threads to finish
        endLatch.await();
        assertEquals(5,requestCounter.get(), "Only " + LIMIT + " should pass the rate limiter");
    }

    @Test
    void shouldNotBlockDifferentIP() throws Exception {
        String spammer_ip = "192.168.1.1";
        String regular_ip = "192.168.1." + UUID.randomUUID();

        for(int i = 0; i < 5; i++){
            mvc.perform(post(EndPoints.LOGIN.getPath())
                    .header("X-Forwarded-For", spammer_ip))
                    .andExpect(status().is(not(429)));
        }

        //Trigger rate limiter
        mvc.perform(post(EndPoints.LOGIN.getPath())
                        .header("X-Forwarded-For", spammer_ip))
                .andExpect(status().isTooManyRequests());

        //Try With Different ip address
        mvc.perform(post(EndPoints.LOGIN.getPath())
                        .header("X-Forwarded-For", regular_ip))
                .andExpect(status().is(not(429)));
    }
}

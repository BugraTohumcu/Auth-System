package com.bugra.filter.login_register.ratelimiter;

import com.bugra.enums.EndPoints;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.AdditionalMatchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class LoginRateLimiterConcurrencyTest {

    private final Logger logger = LoggerFactory.getLogger(LoginRateLimiterConcurrencyTest.class);
    private final int LIMIT = 5;

    @Autowired
    MockMvc mvc;

    @Test
    void filterConcurrencyTest() throws Exception {

        String spammer_ip = "192.168.1.1";
        String regular_ip = "192.168.1" + UUID.randomUUID();
        String spammerUser = """
                {
                    "password":"Abc123",
                    "email":"necmiK@g.com"
                }
                """;
        String regularUser = """
                {
                    "password":"Abc123",
                    "email":"ismetK@g.com"
                }
                """;

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
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(spammerUser)
                            .header("X-Forwarded-For", spammer_ip))
                            .andReturn();

                    int status = res.getResponse().getStatus();
                    if(status == 200){
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

        /**
         * This post request should be called without triggering the rate limiter
         * This tests that different ip addresses dos not affect each other
         * */
        mvc.perform(post(EndPoints.LOGIN.getPath())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regularUser)
                        .header("X-Forwarded-For", regular_ip))
                .andExpect(status().isOk());


        assertEquals(5,requestCounter.get(), "Only " + LIMIT + " should pass the rate limiter");
    }
}

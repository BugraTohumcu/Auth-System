package com.bugra.filter.login_register.ratelimiter;

import com.bugra.dto.ResponsePattern;
import com.bugra.enums.EndPoints;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.UUID;

import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LoginRateLimiterIntegrationTest{

    private final int LIMIT = 5;
    private final long WINDOW_SIZE  = Duration.ofSeconds(20).toMillis();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;



    @Test
    void shouldBlockRequestAfterLimit() throws Exception {
        String ip = "192.168.1" + UUID.randomUUID();
        String testUser = """
                {
                    "password":"Abc123",
                    "email":"necmiK@g.com"
                }
                """;
        for(int i = 0; i < 5; i++){
            mvc.perform(post(EndPoints.LOGIN.getPath())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(testUser)
                    .header("X-Forwarded-For", ip))
                    .andExpect(status().isOk());
        }

        mvc.perform(post(EndPoints.LOGIN.getPath())
                .contentType(MediaType.APPLICATION_JSON)
                .content(testUser)
                .header("X-Forwarded-For", ip))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(result -> {
                    ResponsePattern<?> res = mapper.readValue(
                        result.getResponse().getContentAsString(),
                        ResponsePattern.class
                    );

                    assert !res.success();
                    assert res.data() == null;
                });
    }


    @Test
    void shouldResetWindow() throws Exception {
        String ip = "192.168.1." + UUID.randomUUID();
        String testUser = """
                {
                    "password":"Abc123",
                    "email":"necmiK@g.com"
                }
                """;
        for(int i = 0; i < LIMIT ; i++){
            mvc.perform(post(EndPoints.LOGIN.getPath())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(testUser)
                    .header("X-Forwarded-For", ip))
                    .andExpect(status().is(not(429)));
        }

        // This request going to trigger rate limiter
        mvc.perform(post(EndPoints.LOGIN.getPath())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(testUser)
                        .header("X-Forwarded-For", ip))
                .andExpect(status().isTooManyRequests());


        Thread.sleep(WINDOW_SIZE + 1000 );


        mvc.perform(post(EndPoints.LOGIN.getPath())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(testUser)
                        .header("X-Forwarded-For", ip))
                .andExpect(status().is(not(429)));


    }
}
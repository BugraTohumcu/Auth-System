package com.bugra.support;

import com.bugra.filter.ratelimiter.LoginRateLimiter;
import com.bugra.filter.ratelimiter.RequestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test helper class for simulating concurrent access to the LoginRateLimiter logic.
 * <p>Purpose:
 * <ul>
 *  <li>To verify the thread-safety of LoginRateLimiter's request counting and window logic.</li>
 *  <li>Only used in unit/concurrency tests.</li>
 *  <li>Not part of production code or Spring context.</li>
 * </ul>
 * <p>Note:
 * This class mimics the rate limiting behavior of LoginRateLimiter in memory,
 * allowing deterministic and fast concurrency tests without HTTP overhead.
 */
public class LoginRateLimiterTestHelper {

    private final Logger logger = LoggerFactory.getLogger(LoginRateLimiterTestHelper.class);
    private final int MAX_REQUEST = 5;
    private final long WINDOW_SIZE = Duration.ofSeconds(20).toMillis();
    private final Map<String, RequestInfo> requestMap = new ConcurrentHashMap<>();

    public boolean tryConsume(String ip){

        RequestInfo requestInfo = requestMap.computeIfAbsent(ip, k ->
                new RequestInfo(
                        System.currentTimeMillis(),
                        new AtomicInteger(0)
                )
        );
        synchronized (requestInfo){

            long now = System.currentTimeMillis();
            if(now - requestInfo.getWindowStart() >= WINDOW_SIZE){
                logger.debug("Rate limit window reset for IP: {}", ip);
                requestInfo.setWindowStart(now);
                requestInfo.getCount().set(1);
            }else {
                requestInfo.getCount().incrementAndGet();
            }

            if(requestInfo.getCount().get() > MAX_REQUEST){
                logger.warn("Rate limit exceed for IP: {}",ip);
                return false;
            }

        }
        logger.info("Rate limit does not exceed for IP: {}", ip);
        return true;
    }
}

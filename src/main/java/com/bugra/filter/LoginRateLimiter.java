package com.bugra.filter;

import com.bugra.dto.ResponsePattern;
import com.bugra.enums.EndPoints;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class LoginRateLimiter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(LoginRateLimiter.class);
    private final int MAX_REQUEST = 5;
    private final long WINDOW_SIZE = Duration.ofSeconds(20).toMillis();

    private final Map<String, RequestInfo> requestMap = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException
    {

        if(request.getRequestURI().startsWith(EndPoints.LOGIN.getPath())){
            String ip = request.getRemoteAddr();

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
                    ObjectMapper mapper = new ObjectMapper();
                    ResponsePattern<String> res = new ResponsePattern<>
                            (
                                    HttpStatus.TOO_MANY_REQUESTS.name(),
                                    null,
                                    false
                            );

                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setContentType("application/json");
                    response.getWriter().write(mapper.writeValueAsString(res));
                    return;
                }

            }

        }

        filterChain.doFilter(request,response);
    }

}

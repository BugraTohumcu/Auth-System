package com.bugra.filter;

import com.bugra.dto.ResponsePattern;
import com.bugra.enums.EndPoints;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class LoginRateLimiter extends OncePerRequestFilter {

    private final int MAX_REQUEST = 5;
    private final long WINDOW_SIZE = Duration.ofSeconds(30).toMillis();

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

            int count = requestInfo.getCount().incrementAndGet();

            if(System.currentTimeMillis() - requestInfo.getWindowStart() >= WINDOW_SIZE){
                requestInfo.getCount().set(0);
                filterChain.doFilter(request,response);
            }

            if(count > MAX_REQUEST){
                ObjectMapper mapper = new ObjectMapper();
                ResponsePattern<String> res = new ResponsePattern<>
                        (
                        HttpStatus.TOO_MANY_REQUESTS.toString(),
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

}

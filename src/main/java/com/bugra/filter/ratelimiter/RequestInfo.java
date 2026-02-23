package com.bugra.filter.ratelimiter;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.concurrent.atomic.AtomicInteger;

@Getter
@Setter
@AllArgsConstructor
public class RequestInfo {
    private long windowStart;
    private AtomicInteger count;
}

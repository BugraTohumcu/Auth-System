package com.bugra.service;

import com.bugra.repo.RefreshTokenRepo;
import org.springframework.stereotype.Service;

import java.util.concurrent.ScheduledExecutorService;

@Service
public class TokenCleanupService {

    private RefreshTokenRepo refreshTokenRepo;
    private ScheduledExecutorService scheduler;

    public TokenCleanupService(RefreshTokenRepo refreshTokenRepo) {
        this.refreshTokenRepo = refreshTokenRepo;
    }



}

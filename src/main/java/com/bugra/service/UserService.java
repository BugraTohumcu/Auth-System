package com.bugra.service;

import com.bugra.dto.LoginUser;
import com.bugra.dto.RegisterUser;
import com.bugra.exceptions.UserExistException;
import com.bugra.exceptions.UserNotFoundException;
import com.bugra.model.User;
import com.bugra.repo.UserRepo;
import com.bugra.shared.AuthMessages;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(UserRepo userRepo, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public User register(RegisterUser newUser){
        userRepo.findByEmail(newUser.email())
                .ifPresent(u-> {
                    throw new UserExistException(AuthMessages.EMAIL_ALREADY_EXISTS);
                });

        User user = new User();
        user.setPassword(passwordEncoder.encode(newUser.password()));
        user.setEmail(newUser.email().trim());
        user.setUsername(newUser.username());
        userRepo.save(user);
       return user;
    }

    @Transactional
    public User login(@Valid LoginUser loginUser) {
        User user = userRepo.findByEmail(loginUser.email())
                .orElseThrow(() -> new UserNotFoundException(AuthMessages.INVALID_CREDENTIALS));

        if(!passwordEncoder.matches(loginUser.password(),user.getPassword())){
            throw new UsernameNotFoundException(AuthMessages.INVALID_CREDENTIALS);
        }
        return user;
    }

    public User getUser(HttpServletRequest request) {
        String userId = jwtService.getUserIdFromCookieService(request);
        return userRepo.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException(AuthMessages.USER_NOT_FOUND));
    }
}

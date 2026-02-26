package com.bugra.security;

import com.bugra.enums.EndPoints;
import com.bugra.service.CookieService;
import com.bugra.service.JwtService;
import com.bugra.service.UserDetailsServiceImp;
import com.bugra.enums.Token;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final UserDetailsServiceImp userDetailsServiceImp;
    private final JwtService jwtService;
    private final CookieService cookieService;

    private final List<String> WHITELIST = List.of(
            EndPoints.LOGIN.getPath(),
            EndPoints.REGISTER.getPath(),
            EndPoints.REFRESH.getPath()
    );

    public JwtFilter(UserDetailsServiceImp userDetailsServiceImp, JwtService jwtService, CookieService cookieService) {
        this.userDetailsServiceImp = userDetailsServiceImp;
        this.jwtService = jwtService;
        this.cookieService = cookieService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            String path = request.getRequestURI();
            if(WHITELIST.stream().anyMatch(path::startsWith)){
                filterChain.doFilter(request,response);
                return;
            }

            String accessToken = cookieService.extractTokenFromCookies(Token.access_token.toString(), request);
            String email = jwtService.getUserMailFromToken(accessToken);

            if(StringUtils.hasText(email) && SecurityContextHolder.getContext().getAuthentication() == null){
                UserDetails userDetails = userDetailsServiceImp.loadUserByUsername(email);
                if(userDetails!= null && jwtService.isTokenValid(accessToken,userDetails)){
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }

            }
            filterChain.doFilter(request,response);
        }catch (Exception e){
            logger.error(e.getMessage());
            request.setAttribute("jwt_error", e.getMessage());
            filterChain.doFilter(request, response);
        }
    }
}

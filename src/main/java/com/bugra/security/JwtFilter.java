package com.bugra.security;

import com.bugra.enums.EndPoints;
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

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final UserDetailsServiceImp userDetailsServiceImp;
    private final JwtService jwtService;

    public JwtFilter(UserDetailsServiceImp userDetailsServiceImp, JwtService jwtService) {
        this.userDetailsServiceImp = userDetailsServiceImp;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            String path = request.getRequestURI();
            if(path.startsWith(EndPoints.LOGIN.getPath()) || path.startsWith(EndPoints.REGISTER.getPath())){
                filterChain.doFilter(request,response);
                return;
            }

            String accessToken = jwtService.getTokenFromCookie(Token.access_token.toString(), request);
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

package com.sistemasactivos.ms.accessmgt.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sistemasactivos.ms.accessmgt.service.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        AuthCredentials authCredentials = new AuthCredentials();

        try {
            authCredentials = new ObjectMapper().readValue(request.getReader(), AuthCredentials.class);
        } catch (IOException e) {
            throw new AuthenticationCredentialsNotFoundException("Error al obtener las credenciales de autenticación, error: " + e.getMessage() + ", causa: " + e.getCause());
        }

        UsernamePasswordAuthenticationToken usernamePAT = new UsernamePasswordAuthenticationToken(
                authCredentials.getEmail(),
                authCredentials.getPassword(),
                Collections.emptyList()
        );

        System.out.println("Intentando autenticar: " + usernamePAT.getName() + " " + usernamePAT.getCredentials());

        return getAuthenticationManager().authenticate(usernamePAT);
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("Autenticación exitosa");

        UserDetailsImpl userDetails = (UserDetailsImpl) authResult.getPrincipal();
        String token = TokenUtils.createToken(userDetails.getName(), userDetails.getUsername());

        System.out.println("Token: " + token);

        // Obtener la fecha de expiración del token
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(TokenUtils.ACCESS_TOKEN_SECRET.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
        Date expiration = claims.getExpiration();

        if (expiration != null) {
            System.out.println("Fecha de expiración del token: " + expiration);
        } else {
            System.out.println("El token no contiene información de fecha de expiración");
        }

        response.addHeader("Authorization", "Bearer " + token);
        response.addHeader("Role", " " + userDetails.getAuthorities());
        response.getWriter().flush();

        super.successfulAuthentication(request, response, chain, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("Autenticación fallida: " + failed.getMessage());
        // Manejar la autenticación fallida
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Authentication failed");
    }

}

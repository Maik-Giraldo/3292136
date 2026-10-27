package com.thebestadso.innovation.filter;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.thebestadso.innovation.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtValidationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException {
        String authHeader = request.getHeader("Authorization");

        // Un token legal debe existir y empezar con Bearer (portador)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Header Authorization is missing in the request\"}");
            return;
        }

        // Remplazamos el bearer por un string vacío, de esta forma solo tenemos el jwt
        String token = authHeader.replace("Bearer ", "");

        try {
            if (jwtService.isTokenValid(token)) {

                // Extraemos los claims del jwt
                String username = jwtService.extractSubject(token);
                Long userId = jwtService.excractUserId(token);
                Long rolId = jwtService.extractRolId(token);

                // Seteamos los atributos por si mas adelante lo necesitamos
                request.setAttribute("username", username);
                request.setAttribute("userId", userId);
                request.setAttribute("rolId", rolId);

                // Si todo está bien, pasamos al siguiente paso, ya sea el controller u otro
                // filtro
                filterChain.doFilter(request, response);
            } else {
                response.setContentType("application/json");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Token is invalid\"}");
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Validation is failed\"}");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return path.startsWith("/api/v1/auth/");
    }
}
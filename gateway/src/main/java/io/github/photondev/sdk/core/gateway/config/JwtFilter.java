package io.github.photondev.sdk.core.gateway.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import io.github.photondev.sdk.core.gateway.service.JwtService;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@RequiredArgsConstructor @Slf4j
public class JwtFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Si pas de header Authorization, continuer sans authentification
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);

            // Valider que le JWT n'est pas vide
            if (jwt.trim().isEmpty()) {
                log.warn("Token JWT vide reçu");
                sendUnauthorizedResponse(response, "Token JWT vide");
                return; // IMPORTANT: Ne pas continuer la chaîne
            }

            if (!jwtService.isTokenValid(jwt)){
                sendUnauthorizedResponse(response, "Token invalide, veuillez vous reconnecter");
                return;
            }

            // Extraire le nom d'utilisateur du token
            final String username = jwtService.extractUsername(jwt);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            log.warn("Erreur JWT: {}", e.getMessage());
            sendUnauthorizedResponse(response, "Token JWT invalide: " + e.getMessage());
            return; // IMPORTANT: Ne pas continuer la chaîne
        } catch (Exception e) {
            log.error("Erreur d'authentification: {}", e.getMessage(), e);
            sendUnauthorizedResponse(response, "Erreur d'authentification");
            return; // IMPORTANT: Ne pas continuer la chaîne
        }
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String jsonResponse = """
                {
                    "error": "Unauthorized",
                    "message": "%s",
                    "status": 401,
                    "timestamp": "%s"
                }
                """.formatted(message, Instant.now());

        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();

        // Endpoints publics qui ne nécessitent pas d'authentification
        return (path.equals("/login") && "POST".equals(method)) ||
                (path.equals("/register") && "POST".equals(method)) ||
                path.startsWith("/api/auth/") ||
                path.startsWith("/api/public/") ||
                path.equals("/health") ||
                path.equals("/actuator/health") ||
                path.equals("/error");
    }
}
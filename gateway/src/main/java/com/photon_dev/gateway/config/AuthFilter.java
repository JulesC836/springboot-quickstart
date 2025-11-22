package com.photon_dev.gateway.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GlobalFilter, Ordered{
    private final WebClient.Builder webClientBuilder;
    
    // Injecter le WebClient configuré avec @LoadBalanced
    public AuthFilter(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 1. Gérer les routes publiques/exclues (ex: /auth/login)
        if (isPublicRoute(request.getURI().getPath())) {
            return chain.filter(exchange); // Laisser passer sans authentification
        }

        // 2. Extraire le jeton Bearer
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);
        

        // 3. Appel non bloquant au Service d'Authentification (Nom logique: 'service-authentification')
        return webClientBuilder.build()
                .get()
                // Appel au service via son nom logique et un endpoint de validation
                .uri("lb://AUTH-SERVICE/auth/validate") 
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .onStatus(status -> status.is4xxClientError(), clientResponse -> Mono.error(new RuntimeException("Token invalide ou expiré")))
                .bodyToMono(AuthValidationResponse.class) // Récupérer la réponse de validation
                .flatMap(validationResponse -> {
                    // 4. Succès: Ajouter l'identité de l'utilisateur aux en-têtes
                    ServerHttpRequest authenticatedRequest = request.mutate()
                            .header("X-User-ID", validationResponse.getUserId())
                            .header("X-User-Roles", validationResponse.getRoles())
                            // Bloquer les en-têtes potentiellement dangereux venant de l'extérieur
                            .headers(h -> h.remove("X-User-ID")) 
                            .build();

                    // 5. Continuer la chaîne de filtres avec la requête modifiée
                    return chain.filter(exchange.mutate().request(authenticatedRequest).build());
                })
                .onErrorResume(e -> unauthorized(exchange)); // Échec: 401 Unauthorized
    }

    // Définit la priorité d'exécution du filtre (doit être élevé pour être exécuté en premier)
    @Override
    public int getOrder() {
        return -1; 
    }

    // Méthodes utilitaires
    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
    
    private boolean isPublicRoute(String path) {
        // Définir ici les chemins qui ne nécessitent pas d'authentification
        return path.contains("/api/auth/login") || path.contains("/api/auth/register") || path.contains("**/actuator/**");
    }

    // Classe simple pour mapper la réponse du Service d'Authentification
    
    @Getter
    @Setter
    private static class AuthValidationResponse {
        private String userId;
        private String roles;
        // + getters et setters
    }
}

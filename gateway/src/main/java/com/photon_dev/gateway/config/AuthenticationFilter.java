package com.photon_dev.gateway.config;


import org.springframework.cloud.gateway.filter.GatewayFilter;

import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;

import reactor.core.publisher.Mono;


@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final WebClient.Builder webClientBuilder;

    public AuthenticationFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    public static class Config { /* Paramètres de config si besoin */ }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 1. Extraire le token (ex: Header Authorization)
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (token == null || !token.startsWith("Bearer ")) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token manquant");
            }

            // 2. Appeler le microservice d'Auth
            return webClientBuilder.build()
                    .post()
                    .uri("lb://AUTH-SERVICE/auth/validate")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .retrieve()
                    .bodyToMono(UserDTO.class) // Ton objet utilisateur
                    .flatMap(user -> {
                        // 3. Succès : On peut ajouter des infos dans les headers pour les services suivants
                        exchange.getRequest().mutate()
                                .header("X-User-Id", user.id().toString())
                                .build();
                        return chain.filter(exchange);
                    })
                    .onErrorResume(e -> Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalide")));
        };
    }
}
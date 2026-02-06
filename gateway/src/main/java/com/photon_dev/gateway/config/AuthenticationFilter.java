package com.photon_dev.gateway.config;

import com.photon_dev.gateway.service.AuthService;
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
    private final AuthService authService;

    public AuthenticationFilter(WebClient.Builder webClientBuilder, AuthService authService) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
        this.authService = authService;
    }

    public static class Config {  }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 1. Extraire le token (ex: Header Authorization)
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (token == null || !token.startsWith("Bearer ")) {
                return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token manquant, veuillez vous identifier"));
            }

            return authService.validateToken(token)
                    .flatMap(user->{
                        exchange.getRequest().mutate()
                                .header("X-User-Id", user.id().toString())
                                .build();
                        return chain.filter(exchange);
                    });
        };


    }
}
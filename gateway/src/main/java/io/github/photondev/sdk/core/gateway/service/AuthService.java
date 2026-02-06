package io.github.photondev.sdk.core.gateway.service;

import io.github.photondev.sdk.core.gateway.dto.UserDTO;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
public class AuthService {

    private final WebClient webClient;
    private final ReactiveRedisOperations<String, UserDTO> redisOperations;
    private final Duration cacheTtl = Duration.ofMillis(30000);

    public AuthService(WebClient.Builder webClientBuilder,
                       ReactiveRedisOperations<String, UserDTO> redisOperations) {
        this.webClient = webClientBuilder.baseUrl("lb://AUTH-SERVICE").build();
        this.redisOperations = redisOperations;
    }

    public Mono<UserDTO> validateToken(String token) {
        String cacheKey = "auth_token:" + token;

        // 1. Chercher dans Redis
        return redisOperations.opsForValue().get(cacheKey)
                .switchIfEmpty(
                        // 2. Si absent, appeler le service d'Auth
                        callAuthService(token)
                                .flatMap(user ->
                                        // 3. Sauvegarder dans Redis avec TTL
                                        redisOperations.opsForValue()
                                                .set(cacheKey, user, cacheTtl)
                                                .thenReturn(user)
                                )
                );
    }

    private Mono<UserDTO> callAuthService(String token) {
        return this.webClient.get()
                .uri("/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(UserDTO.class);
    }
}
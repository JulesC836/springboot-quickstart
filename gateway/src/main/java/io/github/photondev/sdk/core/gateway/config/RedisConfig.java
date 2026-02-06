package io.github.photondev.sdk.core.gateway.config;

import io.github.photondev.sdk.core.gateway.dto.UserDTO; // Remplace par ton vrai package
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Bean
    public ReactiveRedisOperations<String, UserDTO> reactiveRedisOperations(ReactiveRedisConnectionFactory factory) {
        // 1. Configurer le sérialiseur JSON pour UserDTO
        Jackson2JsonRedisSerializer<UserDTO> serializer = new Jackson2JsonRedisSerializer<>(UserDTO.class);

        // 2. Créer le contexte de sérialisation
        RedisSerializationContext.RedisSerializationContextBuilder<String, UserDTO> builder =
                RedisSerializationContext.newSerializationContext(new StringRedisSerializer());

        // On définit les clés comme des Strings et les valeurs comme du JSON
        RedisSerializationContext<String, UserDTO> context = builder.value(serializer).build();

        return new ReactiveRedisTemplate<>(factory, context);
    }
}

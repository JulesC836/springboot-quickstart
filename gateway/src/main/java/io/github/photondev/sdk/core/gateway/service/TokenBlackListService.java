package io.github.photondev.sdk.core.gateway.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class TokenBlackListService {
    private final StringRedisTemplate redisTemplate;

    private static final String BLACKLIST_KEY_PREFIX = "blacklist:jwt:";

    public boolean isBlacklisted(String token) {
        return redisTemplate.hasKey(BLACKLIST_KEY_PREFIX + token);
    }
}

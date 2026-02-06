package io.github.photondev.sdk.core.auth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import io.github.photondev.sdk.core.auth.dto.UserResponse;
import io.github.photondev.sdk.core.auth.model.User;
import io.github.photondev.sdk.core.auth.repository.UserRepo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepo repo;

    
    public List<User> allUsers() {
        List<User> users = new ArrayList<>();

        repo.findAll().forEach(users::add);

        return users;
    }

    public UserResponse sendUser(User user, String token){
        return UserResponse
                .builder()
                .name(user.getName())
                .username(user.getUsername())
                .role(user.getRole())
                .access_token(token)
                .build();
    }

    public User getByUsername(String username){
        return repo.findByUsername(username).get();
    }
    
}

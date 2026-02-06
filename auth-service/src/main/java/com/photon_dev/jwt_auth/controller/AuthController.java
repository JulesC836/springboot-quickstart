package com.photon_dev.jwt_auth.controller;

import org.springframework.web.bind.annotation.RestController;

import com.photon_dev.jwt_auth.dto.LoginRequest;
import com.photon_dev.jwt_auth.dto.RegisterRequest;
import com.photon_dev.jwt_auth.dto.UserResponse;
import com.photon_dev.jwt_auth.model.AuthValidationResponse;
import com.photon_dev.jwt_auth.model.User;
import com.photon_dev.jwt_auth.service.AuthService;
import com.photon_dev.jwt_auth.service.JwtService;
import com.photon_dev.jwt_auth.service.RedisTokenBlacklistService;
import com.photon_dev.jwt_auth.service.TokenBlacklistService;
import com.photon_dev.jwt_auth.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final RedisTokenBlacklistService redisTokenBlacklistService;

    @GetMapping("/home")
    public String homView() {
        return "Welcome";
    }

    @PostMapping("/register/")
    public ResponseEntity<?> saveUser(@RequestBody RegisterRequest request) throws Exception {
        request.setRole("USER");
        try {
            User user = authService.signUp(request);
            UserResponse newUser = userService.sendUser(user, null);
            return ResponseEntity.ok(newUser);
        } catch (Exception e) {
            return new ResponseEntity<>("Nom d'utilisateur déjà pris, faut changer " + e.getMessage(), HttpStatus.CONFLICT);
        }

    }

    @PostMapping("/login/")
    public ResponseEntity<?> Authenticate(@RequestBody LoginRequest cred) throws Exception {
        try {

            String token = authService.login(cred);

            userService.getByUsername(cred.getUsername());
            UserResponse authedUser = userService.sendUser(
                    userService.getByUsername(cred.getUsername()),
                    token);
            return ResponseEntity.ok(authedUser);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Mauvaises informations d'identification pour: "+ cred.getUsername(), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>("Erreur d'authentification: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<AuthValidationResponse> validateToken(
            @RequestHeader("Authorization") String authorizationHeader) {

        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);

        if ( authService.validate(token)) {
            // 2. Extraire les données de l'utilisateur du jeton (ou d'une BDD)

            AuthValidationResponse response = new AuthValidationResponse(authService.getUserId(token), authService.getUserRole(token));
            return ResponseEntity.ok(response);
        } else {
            // Jeton invalide
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/control/register/")
    public ResponseEntity<?> saveAdmin(@RequestBody RegisterRequest request) throws Exception {
        request.setRole("ADMIN");
        User user = authService.signUp(request);
        if (user == null) {
            return new ResponseEntity<>("Non d'utilisateur déjà pris, veuillez changer ", HttpStatus.CONFLICT);
        }
        UserResponse newUser = userService.sendUser(user, null);
        return ResponseEntity.ok(newUser);

    }

    @PostMapping("/logout/")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authorizationHeader) {
        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);
        try{
            redisTokenBlacklistService.add(token);
            return ResponseEntity.ok("Vous avez été déconnecté");
        }catch(Exception e){
            return new ResponseEntity<>("Erreur lors de la déconnexion: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }

    }

}

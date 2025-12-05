# Spring Boot Starter - Configuration

## Configuration des secrets

### Fichier secrets.yaml

Créer le fichier `auth-service/src/main/resources/secrets.yaml`. Ce fichier contient les configurations sensibles :

```yaml
security:
  jwt:
    secret-key: <votre-clé-secrète-jwt>
    expiration-time: 3600000  # 1 heure en millisecondes

spring:
  datasource:
    driver-class-name: org.mariadb.jdbc.Driver
    url: jdbc:mariadb://localhost:3306/jwt_auth_user
    username: <nom-utilisateur-db>
    password: <mot-de-passe-db>
```

### Variables à configurer

- `security.jwt.secret-key` : Clé secrète pour signer les tokens JWT (minimum 256 bits)
- `security.jwt.expiration-time` : Durée de validité des tokens en millisecondes
- `spring.datasource.url` : URL de connexion à la base de données MariaDB
- `spring.datasource.username` : Nom d'utilisateur de la base de données
- `spring.datasource.password` : Mot de passe de la base de données

### Sécurité

⚠️ **Important** : Ne jamais commiter le fichier `secrets.yaml` avec de vraies valeurs. Ajoutez-le au `.gitignore`.
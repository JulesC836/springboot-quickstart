# Étape 1 : Compilation
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
COPY src /home/app/src
COPY pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package

# Étape 2 : Image finale (légère)
FROM maven:3.9-eclipse-temurin-21-alpine
COPY --from=build /home/app/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
# Multi-stage Docker build for SignaTrust PoC
# Build stage
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/signatrust-poc-0.0.1-SNAPSHOT.jar app.jar

# Expose the API port
EXPOSE 8080

# Run the stateless Java binary
ENTRYPOINT ["java","-jar","/app/app.jar"]

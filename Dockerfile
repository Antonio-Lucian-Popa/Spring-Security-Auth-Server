# 1. Use official Maven image to build the app
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# 2. Use a lightweight JRE image to run the app
FROM eclipse-temurin:17-jdk-alpine

VOLUME /tmp
WORKDIR /app

# Copy built jar from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Set environment variables (can be overridden in docker-compose or Kubernetes)
ENV SPRING_PROFILES_ACTIVE=prod

# Expose port (as defined in application.yml)
EXPOSE 8080

# Run the app
ENTRYPOINT ["java", "-jar", "app.jar"]

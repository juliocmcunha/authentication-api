# ---- build stage ----
FROM gradle:8.10-jdk21 AS build
WORKDIR /workspace
COPY . .
RUN gradle bootJar --no-daemon

# ---- run stage ----
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

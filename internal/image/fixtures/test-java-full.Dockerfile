# Use the official OpenJDK image as the base image
# TODO: This has been deprecated and we might want to switch to another image
FROM openjdk:25-jdk-slim@sha256:34f10f3a1a5b638184ebd1c5c1b4aa4c49616ae3e5c1e845f0ac18c5332b5c6f

RUN apt update && apt install -y maven

# Set the working directory inside the container
WORKDIR /app

# Copy the project files into the container
COPY ./java-fixture/app .

# Download dependencies with maven
RUN mvn clean package

FROM alpine:3.21@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099

RUN apk update && apk add openjdk21-jre

WORKDIR /app

COPY --from=0 /app/target/my-app-1.0-SNAPSHOT-jar-with-dependencies.jar target.jar

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "target.jar"]

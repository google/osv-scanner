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

FROM eclipse-temurin:21-jre-alpine-3.21@sha256:7832115c38e9359db1156f94f9228fdf1341388f17dbd9df6c45727d233d1f5f

WORKDIR /app

COPY --from=0 /app/target/my-app-1.0-SNAPSHOT-jar-with-dependencies.jar target.jar

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "target.jar"]

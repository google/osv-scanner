# Use the official OpenJDK image as the base image
FROM openjdk:25-jdk-slim@sha256:34f10f3a1a5b638184ebd1c5c1b4aa4c49616ae3e5c1e845f0ac18c5332b5c6f

RUN apt update && apt install -y maven

# Set the working directory inside the container
WORKDIR /app

# Copy the project files into the container
COPY ./java-fixture .

# Download dependencies with maven
RUN mvn dependency:get \
  -Dartifact=org.apache.kafka:kafka-clients:3.6.0 \
  -Ddest=./kafka-clients-3.6.0.jar

RUN javac -cp kafka-clients-3.6.0.jar SimpleProducer.java
RUN jar -cvf simple-producer.jar SimpleProducer.class

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "simple-producer.jar"]

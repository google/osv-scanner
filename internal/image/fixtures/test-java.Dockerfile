# Use the official OpenJDK image as the base image
FROM openjdk:25-jdk-slim

RUN apt update && apt install -y maven

# Set the working directory inside the container
WORKDIR /app

# Copy the project files into the container
COPY ./java-fixture .

# Download dependencies and build the project using Maven
# RUN mvn clean package

RUN mvn dependency:get \
  -Dartifact=org.apache.kafka:kafka-clients:3.6.0 \
  -Ddest=./kafka-clients-3.6.0.jar

RUN javac -cp kafka-clients-3.6.0.jar SimpleProducer.java
RUN jar -cvf simple-producer.jar SimpleProducer.class

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "simple-producer.jar"]

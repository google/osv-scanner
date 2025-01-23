# Use the official OpenJDK image as the base image
FROM openjdk:25-jdk-slim@sha256:34f10f3a1a5b638184ebd1c5c1b4aa4c49616ae3e5c1e845f0ac18c5332b5c6f

RUN apt update && apt install -y maven

# Set the working directory inside the container
WORKDIR /app

# Copy the project files into the container
COPY ./java-fixture .

RUN javac HelloWorld.java
RUN jar -cvf hello-world.jar HelloWorld.class

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "hello-world.jar"]

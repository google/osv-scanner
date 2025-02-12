# Use the official Debian image as the base
FROM python:3.9-slim-buster@sha256:320a7a4250aba4249f458872adecf92eea88dc6abd2d76dc5c0f01cac9b53990

# Set the working directory in the container
WORKDIR /app

# Copy the rest of the application code into the container
COPY python-fixture/main.py main.py

# Specify the command to run when the container starts
CMD ["python", "main.py"]

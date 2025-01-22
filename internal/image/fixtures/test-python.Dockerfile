# Use the official Debian image as the base
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY ./python-fixture/requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY python-fixture/main.py main.py

# Specify the command to run when the container starts
CMD ["python", "main.py"]

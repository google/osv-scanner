# Use an official Ruby runtime as a parent image.
FROM ruby:4@sha256:342dd3092e25f9d16fc2a5c48c5bb2d9a93717d4f900d005d6e088e2c45d3d19

# Set the working directory in the container.
WORKDIR /usr/src/app

# Copy the Gemfile and Gemfile.lock.
# This is done first to leverage Docker's layer caching.
COPY ./Gemfile* ./

# Install the dependencies.
RUN bundle install

# Copy the rest of the documentation files.
COPY ./ ./

# Expose port 4000 for the Jekyll server.
EXPOSE 4000

# The command to run when the container starts.
# --host 0.0.0.0 is important to make the server accessible from outside the container.
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]

# Use an official Ruby runtime as a parent image.
FROM ruby:4@sha256:a69f361db050bb2c65ec66ef75411bfc4ce2e1d993ba1179fac4e4ba6ecfe91f

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

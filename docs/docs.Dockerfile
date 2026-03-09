# Use an official Ruby runtime as a parent image.
FROM ruby:3@sha256:5c58050b16e00de92e7614bee88cd27865c0bdba262feb44aa838ae5da4431c9

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

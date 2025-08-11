# README

The [OSV-Scanner docs](https://google.github.io/osv-scanner) are hosted on a [GitHub page](https://pages.github.com/).

## Running docs locally (docker)

You can run the docs locally consistently through docker:

```bash
docker build -t osv-scanner-docs -f docs.Dockerfile .
docker run -p 4000:4000 osv-scanner-docs
```

## Running docs locally (native)

To run the docs locally, use :

- Install `ruby (>= 3.1.0)`. This should come with `bundler`.
  - On Debian, you need to install them separately:
    - `ruby`
    - `ruby-bundler`
- In this directory:
  - `bundle config set --local path 'vendor/bundle'` (you can skip this step if serving from this directory, as the config is already saved in `.bundle/config`)
  - `bundle install`
  - `bundle exec jekyll serve`

Here's the full documentation on github for running the [docs locally].

[docs locally]: https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll#building-your-site-locally

## Formatting docs

We use [Prettier](https://prettier.io/) to standardize the format of markdown and config files.

This requires [node/npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) to be installed.

### Running the formatter

Run the following in the project directory:

```shell
./scripts/run_formatters.sh
```

## Documentation theme

We are using the [Just the Docs](https://just-the-docs.github.io/just-the-docs/)
theme.

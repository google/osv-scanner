# README

The [OSV-Scanner docs](https://google.github.io/osv-scanner) are hosted on a [GitHub page](https://pages.github.com/).

## Running docs locally

To run docs locally, you will need [Jekyll](https://jekyllrb.com/docs/installation/) on your machine.

Here are other [pre-requisites] and instructions for running the [docs locally].

[pre-requisites]: https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll#prerequisites
[docs locally]: https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll#building-your-site-locally

## Formatting docs

We use - [Prettier](https://prettier.io/) to standardize the format of markdown and config files.

This requires [node/npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) to be installed.

### Running the formatter

Run the following in the project directory:

```shell
./scripts/run_formatters.sh
```

## Documentation theme

We are using the [Just the Docs](https://just-the-docs.github.io/just-the-docs/)
theme.

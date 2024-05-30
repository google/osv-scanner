#!/usr/bin/env Rscript

install.packages("jsonlite", repos = 'https://cran.r-project.org')

library(utils)
library(jsonlite)

# An array of version comparisons that are known to be unsupported and so
# should be commented out in the generated fixture.
#
# Generally this is because the native implementation has a suspected bug
# that causes the comparison to return incorrect results, and so supporting
# such comparisons in the detector would in fact be wrong.
UNSUPPORTED_COMPARISONS <- c()

download_cran_db <- function() {
  url <- "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip"
  dest <- "cran-db.zip"
  download.file(url, dest, method = "auto")
}

extract_packages_with_versions <- function(osvs) {
  result <- list()

  for (osv in osvs) {
    for (affected in osv$affected) {
      if (affected$package$ecosystem != "CRAN") {
        next
      }

      package <- affected$package$name

      if (!(package %in% names(result))) {
        result[[package]] <- list()
      }

      for (version in affected$versions) {
        tryCatch(
          {
            as.package_version(version)
            result[[package]] <- c(result[[package]], version)
          },
          error = function(e) {
            cat(sprintf("skipping invalid version %s for %s\n", version, package))
          }
        )
      }
    }
  }

  # deduplicate and sort the versions for each package
  for (package in names(result)) {
    result[[package]] <- sort(numeric_version(unique(result[[package]])))
  }

  return(result)
}

is_unsupported_comparison <- function(line) {
  line %in% UNSUPPORTED_COMPARISONS
}

uncomment <- function(line) {
  if (startsWith(line, "#")) {
    return(substr(line, 2, nchar(line)))
  }
  if (startsWith(line, "//")) {
    return(substr(line, 3, nchar(line)))
  }
  return(line)
}

compare <- function(v1, relate, v2) {
  ops <- list('<' = function(result) result < 0,
              '=' = function(result) result == 0,
              '>' = function(result) result > 0)

  return(ops[[relate]](compareVersion(v1, v2)))
}

compare_versions <- function(lines, select="all") {
  has_any_failed <- FALSE

  for (line in lines) {
    line <- trimws(line)

    if (line == "" || grepl("^#", line) || grepl("^//", line)) {
      maybe_unsupported <- trimws(uncomment(line))

      if (is_unsupported_comparison(maybe_unsupported)) {
        cat(sprintf("\033[96mS\033[0m: \033[93m%s\033[0m\n", maybe_unsupported))
      }
      next
    }

    parts <- strsplit(trimws(line), " ")[[1]]
    v1 <- parts[1]
    op <- parts[2]
    v2 <- parts[3]

    r <- compare(v1, op, v2)

    if (!r) {
      has_any_failed <- TRUE
    }

    if (select == "failures" && r) {
      next
    }

    if (select == "successes" && !r) {
      next
    }

    color <- ifelse(r, '\033[92m', '\033[91m')
    rs <- ifelse(r, "T", "F")
    cat(sprintf("%s%s\033[0m: \033[93m%s\033[0m\n", color, rs, line))
  }
  return(has_any_failed)
}

compare_versions_in_file <- function(filepath, select="all") {
  lines <- readLines(filepath)
  return(compare_versions(lines, select))
}

generate_version_compares <- function(versions) {
  comparisons <- character()

  for (i in seq_along(versions)) {
    if (i == 1) {
      next
    }

    comparison <- sprintf("%s < %s", versions[i - 1], versions[i])

    if (is_unsupported_comparison(trimws(comparison))) {
      comparison <- paste("#", comparison)
    }

    comparisons <- c(comparisons, comparison)
  }

  return(comparisons)
}

generate_package_compares <- function(packages) {
  comparisons <- character()

  for (package in names(packages)) {
    versions <- packages[[package]]
    comparisons <- c(comparisons, generate_version_compares(versions))
  }

  # return unique comparisons
  return(unique(comparisons))
}

fetch_packages_versions <- function() {
  download_cran_db()
  osvs <- list()

  with_zip <- unzip("cran-db.zip", list = TRUE)

  for (fname in with_zip$Name) {
    osv <- jsonlite::fromJSON(unzip("cran-db.zip", files = fname, exdir = tempdir()), simplifyDataFrame = FALSE)
    osvs <- c(osvs, list(osv))
  }

  return(extract_packages_with_versions(osvs))
}

outfile <- "internal/semantic/fixtures/cran-versions-generated.txt"

packs <- fetch_packages_versions()
writeLines(generate_package_compares(packs), outfile, sep = "\n")
cat("\n")

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show <- Sys.getenv("VERSION_GENERATOR_PRINT", "failures")

did_any_fail <- compare_versions_in_file(outfile, show)

if (did_any_fail) {
  q(status = 1)
}

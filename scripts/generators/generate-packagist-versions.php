<?php

//

// An array of version comparisons that are known to be unsupported and so
// should be commented out in the generated fixture.
//
// Generally this is because the native implementation has a suspected bug
// that causes the comparison to return incorrect results, and so supporting
// such comparisons in the detector would in fact be wrong.
$UNSUPPORTED_COMPARISONS = [];

function isUnsupportedComparison(string $line): bool
{
  global $UNSUPPORTED_COMPARISONS;

  return in_array($line, $UNSUPPORTED_COMPARISONS, true);
}

function uncomment(string $line): string
{
  if (str_starts_with($line, '#')) {
    return substr($line, 1);
  }

  if (str_starts_with($line, '//')) {
    return substr($line, 2);
  }

  return $line;
}

function downloadPackagistDb(): string
{
  $url = 'https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip';

  $file    = './packagist-db.zip';
  $current = file_get_contents($url);
  file_put_contents($file, $current);

  return $file;
}

/**
 * @throws RuntimeException
 */
function openDbZip(string $path): ZipArchive
{
  $zip = new ZipArchive();
  if ($zip->open($path, ZipArchive::RDONLY) === false) {
    throw new RuntimeException('failed to read zip archive');
  }

  return $zip;
}

/**
 * @throws JsonException
 * @throws RuntimeException
 */
function fetchPackageVersions(): array
{
  $dbPath = downloadPackagistDb();
  $dbZip  = openDbZip($dbPath);

  $osvs = [];

  for ($i = 0; $i < $dbZip->numFiles; $i++) {
    $file = $dbZip->getFromIndex($i);

    if ($file === false) {
      throw new RuntimeException('failed to read a file from db zip');
    }

    $osvs[] = json_decode($file, true, 512, JSON_THROW_ON_ERROR);
  }

  $packages = [];

  foreach ($osvs as $osv) {
    foreach ($osv['affected'] as $affected) {
      if ($affected['package']['ecosystem'] !== 'Packagist') {
        continue;
      }

      $package = $affected['package']['name'];

      if (!isset($packages[$package])) {
        $packages[$package] = [];
      }

      if (empty($affected['versions'])) {
        continue;
      }

      foreach ($affected['versions'] as $version) {
        $packages[$package][] = $version;
      }
    }
  }

  return array_map(static function ($versions) {
    $uniq = array_unique($versions);
    usort($uniq, static fn($a, $b) => version_compare(ltrim($a, "vV"), ltrim($b, "vV")));

    return $uniq;
  }, $packages);
}

/**
 * Normalizes the previous version such that it will compare "correctly" to the current version,
 * by ensuring that they both have the same "v" prefix (or lack of).
 *
 * Whether the "v" prefix is present on the normalized previous version depends on
 * its presences in the current version; this ensure we will have _some_ versions that
 * do have the "v" prefix, rather than it being present on _none_ or _all_ versions.
 *
 * @param string $currentVersion
 * @param string $previousVersion
 *
 * @return string
 */
function normalizePrevVersion(string $currentVersion, string $previousVersion): string
{
  if (str_starts_with($currentVersion, "v")) {
    $previousVersion = ltrim($previousVersion, "vV");

    return "v$previousVersion";
  }

  if (str_starts_with($currentVersion, "V")) {
    $previousVersion = ltrim($previousVersion, "vV");

    return "V$previousVersion";
  }

  return ltrim($previousVersion, "vV");
}

function generateVersionCompares(array $versions): array
{
  $comparisons = [];

  foreach ($versions as $index => $version) {
    if ($index === 0) {
      continue;
    }

    $prevVersion = normalizePrevVersion($version, $versions[$index - 1]);
    $op          = version_compare($prevVersion, $version) === 0 ? "=" : "<";

    $comparison = "$prevVersion $op $version";

    if (isUnsupportedComparison($comparison)) {
      $comparison = "# $comparison";
    }

    $comparisons[] = $comparison;
  }

  return $comparisons;
}

function generatePackageCompares(array $packages): array
{
  $comparisons = [];

  foreach ($packages as $versions) {
    $comparisons[] = generateVersionCompares($versions);
  }

  return array_merge(...$comparisons);
}

function compareVersions(array $lines, string $select = "all"): bool
{
  $hasAnyFailed = false;

  foreach ($lines as $line) {
    $line = trim($line);

    if (empty($line) || str_starts_with($line, "#") || str_starts_with($line, "//")) {
      $maybeUnsupported = trim(uncomment($line));

      if (isUnsupportedComparison($maybeUnsupported)) {
        echo "\033[96mS\033[0m: \033[93m$maybeUnsupported\033[0m\n";
      }

      continue;
    }

    [$v1, $op, $v2] = explode(" ", $line);

    $r = version_compare($v1, $v2, $op);

    if (!$r) {
      $hasAnyFailed = true;
    }

    if ($select === "failures" && $r === true) {
      continue;
    }

    if ($select === "successes" && $r !== true) {
      continue;
    }

    $color = $r ? "\033[92m" : "\033[91m";
    $rs    = $r ? "T" : "F";
    echo "$color$rs\033[0m: \033[93m$line\033[0m\n";
  }

  return $hasAnyFailed;
}

$outfile = "internal/semantic/fixtures/packagist-versions-generated.txt";

/** @noinspection PhpUnhandledExceptionInspection */
$packages = fetchPackageVersions();

file_put_contents($outfile, implode("\n", array_unique(generatePackageCompares($packages))) . "\n");

// set this to either "failures" or "successes" to only have those comparison results
// printed; setting it to anything else will have all comparison results printed
$show = getenv("VERSION_GENERATOR_PRINT") ?: "failures";

$didAnyFail = compareVersions(explode("\n", file_get_contents($outfile)), $show);

if ($didAnyFail === true) {
  exit(1);
}

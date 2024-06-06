import org.apache.maven.artifact.versioning.ComparableVersion;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Script for generating a list of maven version comparison fixtures based off
 * every version mentioned in the OSV Maven database, sorted using the native
 * Maven implementation.
 * <p>
 * To run this, you need to ensure copies of the following libraries are present
 * on the class path:
 *
 * <ul>
 * <li><a href="https://search.maven.org/artifact/org.json/json/20220924/bundle"><code>json</code></a></li>
 * <li><a href="https://search.maven.org/artifact/org.apache.maven/maven-artifact/3.8.6/jar"><code>maven-artifact</code></a></li>
 * </ul>
 * The easiest way to do this is by putting the jars into a <code>lib</code> subfolder and then running:
 * <code>
 *   java -cp generators/lib/* generators/GenerateMavenVersions.java
 * </code>
 */
public class GenerateMavenVersions {
  /**
   * An array of version comparisons that are known to be unsupported and so
   * should be commented out in the generated fixture.
   * <p>
   * Generally this is because the native implementation has a suspected bug
   * that causes the comparison to return incorrect results, and so supporting
   * such comparisons in the detector would in fact be wrong.
   */
  private static final String[] UNSUPPORTED_COMPARISONS = {
    "0.0.0-2021-07-06T00-28-13-573087f7 < 0.0.0-2021-07-06T01-14-42-efe42242",
    "0.0.0-2021-12-06T00-08-57-89a33731 < 0.0.0-2021-12-06T01-21-56-e3888760",
    "0.0.0-2022-02-01T00-45-53-0300684a < 0.0.0-2022-02-01T05-45-16-7258ece0",
    "0.0.0-2022-02-28T00-18-39-7fe0d845 < 0.0.0-2022-02-28T04-15-47-83c97ebe",
    "0.0.0-2022-04-29T00-08-11-7086a3ec < 0.0.0-2022-04-29T01-20-09-b424f986",
    "0.0.0-2022-06-14T00-21-33-f21869a7 < 0.0.0-2022-06-14T02-56-29-1db980e0",
    "0.0.0-2022-08-16T00-14-19-aeae3dc3 < 0.0.0-2022-08-16T10-34-26-7a56f709",
    "0.0.0-2022-08-22T00-46-32-4652d3db < 0.0.0-2022-08-22T06-46-40-e7409ac5",
    "0.0.0-2022-10-31T00-42-12-322ba6b9 < 0.0.0-2022-10-31T01-23-06-c6652489",
    "0.0.0-2022-10-31T07-00-43-71eccd49 < 0.0.0-2022-10-31T07-05-43-97874976",
    "0.0.0-2022-12-01T00-02-29-fe8d6705 < 0.0.0-2022-12-01T01-56-22-5b442198",
    "0.0.0-2022-12-18T00-44-34-a222f475 < 0.0.0-2022-12-18T01-45-19-fec81751",
    "0.0.0-2023-03-20T00-52-15-4b4c0e7 < 0.0.0-2023-03-20T01-49-44-80e3135"
  };

  public static boolean isUnsupportedComparison(String line) {
    return Arrays.stream(UNSUPPORTED_COMPARISONS).anyMatch(line::equals);
  }

  public static String uncomment(String line) {
    if(line.startsWith("#")) {
      return line.substring(1);
    }

    if(line.startsWith("//")) {
      return line.substring(2);
    }

    return line;
  }

  public static String downloadMavenDb() throws IOException {
    URL website = new URL("https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip");
    String file = "./maven-db.zip";

    ReadableByteChannel rbc = Channels.newChannel(website.openStream());

    try(FileOutputStream fos = new FileOutputStream(file)) {
      fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
    }

    return file;
  }

  public static Map<String, List<String>> fetchPackageVersions() throws IOException {
    String dbPath = downloadMavenDb();
    List<JSONObject> osvs = loadOSVs(dbPath);

    Map<String, List<String>> packages = new HashMap<>();

    osvs.forEach(osv -> osv.getJSONArray("affected").forEach(aff -> {
      JSONObject affected = (JSONObject) aff;

      if(affected.getJSONObject("package").getString("ecosystem").equals("Maven")) {
        return;
      }

      String pkgName = affected.getJSONObject("package").getString("name");

      if(!affected.has("versions")) {
        return;
      }
      JSONArray versions = affected.getJSONArray("versions");

      packages.putIfAbsent(pkgName, new ArrayList<>());

      if(versions.isEmpty()) {
        return;
      }

      versions.forEach(version -> packages.get(pkgName).add((String) version));
    }));

    packages.forEach((key, _ignore) -> packages.put(
      key,
      packages.get(key)
              .stream()
              .distinct()
              .sorted(Comparator.comparing(ComparableVersion::new))
              .collect(Collectors.toList())
    ));

    return packages;
  }

  public static List<JSONObject> loadOSVs(String pathToDbZip) throws IOException {
    List<JSONObject> osvs = new ArrayList<>();

    try(ZipFile zipFile = new ZipFile(pathToDbZip)) {
      Enumeration<? extends ZipEntry> entries = zipFile.entries();

      while(entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        InputStream stream = zipFile.getInputStream(entry);

        BufferedReader streamReader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        StringBuilder responseStrBuilder = new StringBuilder();

        String inputStr;
        while((inputStr = streamReader.readLine()) != null) {
          responseStrBuilder.append(inputStr);
        }
        osvs.add(new JSONObject(responseStrBuilder.toString()));
      }
    }

    return osvs;
  }

  public static void writeToFile(String outfile, List<String> lines) throws IOException {
    try(PrintWriter writer = new PrintWriter(outfile, StandardCharsets.UTF_8)) {
      lines.forEach(writer::println);
    }
  }

  public static boolean compareVers(String version1, String op, String version2) {
    ComparableVersion v1 = new ComparableVersion(version1);
    ComparableVersion v2 = new ComparableVersion(version2);

    int r = v1.compareTo(v2);

    if(op.equals("=")) {
      return r == 0;
    }

    if(op.equals("<")) {
      return r < 0;
    }

    if(op.equals(">")) {
      return r > 0;
    }

    throw new RuntimeException("unsupported comparison operator " + op);
  }

  public static boolean compareVersions(List<String> lines, String select) {
    boolean didAnyFail = false;

    for(String line : lines) {
      line = line.trim();

      if(line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
        String maybeUnsupported = uncomment(line).trim();

        if(isUnsupportedComparison(maybeUnsupported)) {
          System.out.printf("\033[96mS\033[0m: \033[93m%s\033[0m\n", maybeUnsupported);
        }

        continue;
      }

      String[] parts = line.split(" ");
      String v1 = parts[0];
      String op = parts[1];
      String v2 = parts[2];

      boolean r = compareVers(v1, op, v2);

      if(!r) {
        didAnyFail = true;
      }

      if(select.equals("failures") && r) {
        continue;
      }

      if(select.equals("successes") && !r) {
        continue;
      }

      String color = r ? "\033[92m" : "\033[91m";
      String rs = r ? "T" : "F";

      System.out.printf("%s%s\033[0m: \033[93m%s\033[0m\n", color, rs, line);
    }

    return didAnyFail;
  }

  public static boolean compareVersionsInFile(String filepath, String select) throws IOException {
    List<String> lines = new ArrayList<>();

    try(BufferedReader br = new BufferedReader(new FileReader(filepath))) {
      String line = br.readLine();

      while(line != null) {
        lines.add(line);
        line = br.readLine();
      }
    }

    return compareVersions(lines, select);
  }

  public static List<String> generateVersionCompares(List<String> versions) {
    return IntStream.range(1, versions.size()).mapToObj(i -> {
      String currentVersion = versions.get(i);
      String previousVersion = versions.get(i - 1);
      String op = compareVers(currentVersion, "=", previousVersion) ? "=" : "<";

      String comparison = String.format("%s %s %s", previousVersion, op, currentVersion);

      if(isUnsupportedComparison(comparison)) {
        comparison = "# " + comparison;
      }

      return comparison;
    }).collect(Collectors.toList());
  }

  public static List<String> generatePackageCompares(Map<String, List<String>> packages) {
    return packages
             .values()
             .stream()
             .map(GenerateMavenVersions::generateVersionCompares)
             .flatMap(Collection::stream)
             .distinct()
             .collect(Collectors.toList());
  }

  public static String getSelectFilter() {
    // set this to either "failures" or "successes" to only have those comparison results
    // printed; setting it to anything else will have all comparison results printed
    String value = System.getenv("VERSION_GENERATOR_PRINT");

    if(value == null) {
      return "failures";
    }

    return value;
  }

  public static void main(String[] args) throws IOException {
    String outfile = "internal/semantic/fixtures/maven-versions-generated.txt";
    Map<String, List<String>> packages = fetchPackageVersions();

    writeToFile(outfile, generatePackageCompares(packages));

    String show = getSelectFilter();

    boolean didAnyFail = compareVersionsInFile(outfile, show);

    if(didAnyFail) {
      System.exit(1);
    }
  }
}

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

  public static void compareVersions(List<String> lines, String select) {
    lines.forEach(line -> {
      line = line.trim();

      if(line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
        return;
      }

      String[] parts = line.split(" ");
      String v1 = parts[0];
      String op = parts[1];
      String v2 = parts[2];

      boolean r = compareVers(v1, op, v2);

      if(select.equals("failures") && r) {
        return;
      }

      if(select.equals("successes") && !r) {
        return;
      }

      String color = r ? "\033[92m" : "\033[91m";
      String rs = r ? "T" : "F";

      System.out.printf("%s%s\033[0m: \033[93m%s\033[0m\n", color, rs, line);
    });
  }

  public static void compareVersionsInFile(String filepath, String select) throws IOException {
    List<String> lines = new ArrayList<>();

    try(BufferedReader br = new BufferedReader(new FileReader(filepath))) {
      String line = br.readLine();

      while(line != null) {
        lines.add(line);
        line = br.readLine();
      }
    }

    compareVersions(lines, select);
  }

  public static List<String> generateVersionCompares(List<String> versions) {
    return IntStream.range(1, versions.size()).mapToObj(i -> {
      String currentVersion = versions.get(i);
      String previousVersion = versions.get(i - 1);
      String op = compareVers(currentVersion, "=", previousVersion) ? "=" : "<";

      return String.format("%s %s %s", previousVersion, op, currentVersion);
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

  public static void main(String[] args) throws IOException {
    String outfile = "maven-versions-generated.txt";
    Map<String, List<String>> packages = fetchPackageVersions();

    writeToFile(outfile, generatePackageCompares(packages));

    compareVersionsInFile(outfile, "failures");
  }
}

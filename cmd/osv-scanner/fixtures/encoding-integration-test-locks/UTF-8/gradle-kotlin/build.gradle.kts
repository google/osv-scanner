plugins {
  id("java")
}

repositories {
  mavenCentral()
}

dependencies {
  implementation("org.springframework.security:spring-security-crypto:5.7.3")
  testImplementation("junit:junit:4.13.2")
}

dependencyLocking {
  lockAllConfigurations()
}

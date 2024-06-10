plugins {
  `java-library`
}

repositories {
  mavenCentral()
}

dependencies {
  implementation(group = "org.springframework.security", name = "spring-security-crypto", version = "5.7.3")
}

dependencyLocking {
  lockAllConfigurations()
}

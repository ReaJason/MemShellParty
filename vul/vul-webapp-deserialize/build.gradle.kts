plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val dependencyCoordinates = listOf(
    "commons-beanutils:commons-beanutils:1.10.0",
    "commons-beanutils:commons-beanutils:1.9.4",
    "commons-beanutils:commons-beanutils:1.8.3",
    "commons-beanutils:commons-beanutils:1.7.0",
    "commons-beanutils:commons-beanutils:1.6.1",
    "commons-collections:commons-collections:3.2.1",
    "org.apache.commons:commons-collections4:4.0"
)

val filesToCopy = objects.fileCollection().from(
    dependencyCoordinates.map { coordinate ->
        configurations.detachedConfiguration(dependencies.create(coordinate)).apply {}
    }
)

dependencies {
    implementation("com.caucho:hessian:4.0.66")
    providedCompile("javax.servlet:javax.servlet-api:3.1.0")
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

val depDir = file("src/main/webapp/WEB-INF/dep")

tasks.war {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    doFirst {
        copy {
            from(filesToCopy)
            into(depDir)
        }
    }
}

tasks.clean {
    delete(depDir)
}

tasks.test {
    useJUnitPlatform()
}

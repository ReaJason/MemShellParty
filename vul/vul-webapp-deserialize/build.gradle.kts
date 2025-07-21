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

configurations {
    create("cb110")
    create("cb194")
    create("cb183")
    create("cb170")
    create("cb161")
    create("cc321")
    create("cc40")
}

dependencies {
    "cb110"("commons-beanutils:commons-beanutils:1.10.0")
    "cb194"("commons-beanutils:commons-beanutils:1.9.4")
    "cb183"("commons-beanutils:commons-beanutils:1.8.3")
    "cb170"("commons-beanutils:commons-beanutils:1.7.0")
    "cb161"("commons-beanutils:commons-beanutils:1.6.1")
    "cc321"("commons-collections:commons-collections:3.2.1")
    "cc40"("org.apache.commons:commons-collections4:4.0")

    implementation("com.caucho:hessian:4.0.66")
    providedCompile("javax.servlet:javax.servlet-api:3.1.0")
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.war {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    doFirst {
        delete("src/main/webapp/WEB-INF/dep")
        copy {
            from(
                configurations["cb110"],
                configurations["cb194"],
                configurations["cb183"],
                configurations["cb170"],
                configurations["cb161"],
                configurations["cc321"],
                configurations["cc40"]
            )
            into("src/main/webapp/WEB-INF/dep")
        }
    }
}

tasks.clean {
    delete("src/main/webapp/WEB-INF/dep")
}

tasks.test {
    useJUnitPlatform()
}

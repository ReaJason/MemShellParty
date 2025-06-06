plugins {
    id("java")
    id("war")
}

java {
    targetCompatibility = JavaVersion.VERSION_1_8
    sourceCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web:1.5.22.RELEASE")
    providedRuntime("org.springframework.boot:spring-boot-starter-tomcat:1.5.22.RELEASE")
    testImplementation("org.springframework.boot:spring-boot-starter-test:1.5.22.RELEASE")
}

tasks.register("bootJar", Jar::class.java) {
    archiveBaseName.set(project.name)
    archiveVersion.set("")

    from(sourceSets.main.get().output)
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    manifest {
        attributes["Main-Class"] = "com.reajason.javaweb.vul.springboot1.VulSpringboot1Application"
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

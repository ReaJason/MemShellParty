plugins {
    id("com.vanniktech.maven.publish")
}

val isSnapshot = (rootProject.version as String).endsWith("-SNAPSHOT")

mavenPublishing {
    publishToMavenCentral(automaticRelease = true, validateDeployment = true)
    signAllPublications()
    // 快照直传 Sonatype maven-snapshots 端点，不校验 sources/javadoc；不带它们每模块
    // 少 4 个 PUT（两个 jar 及各自 .asc），还省掉 delombok/javadoc 任务。release 保持全量。
    if (isSnapshot) {
        configureBasedOnAppliedPlugins(sourcesJar = false, javadocJar = false)
    }
    coordinates(
        "io.github.reajason",
        project.name,
        rootProject.version as String
    )

    pom {
        name.set("MemShellParty")
        description.set(project.description)
        url.set("https://github.com/ReaJason/MemShellParty")
        inceptionYear.set("2025")
        licenses {
            license {
                name.set("MIT")
                url.set("https://spdx.org/licenses/MIT.html")
            }
        }
        developers {
            developer {
                id.set("reajason")
                name.set("ReaJason")
                url.set("https://reajason.eu.org")
            }
        }
        scm {
            connection.set("scm:git:https://github.com/ReaJason/MemShellParty.git")
            developerConnection.set("scm:git:ssh://github.com/ReaJason/MemShellParty.git")
            url.set("https://github.com/ReaJason/MemShellParty")
        }
    }
}
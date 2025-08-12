plugins {
    id("com.vanniktech.maven.publish")
}

mavenPublishing {
    publishToMavenCentral(true)
    signAllPublications()
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
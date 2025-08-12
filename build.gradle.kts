plugins {
    id("java")
    id("idea")
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "2.0.0-SNAPSHOT"

tasks.register("publishAllToMavenCentral") {
    val isSnapshot = rootProject.version.toString().endsWith("-SNAPSHOT")
    if (isSnapshot) {
        dependsOn(":memshell-party-common:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":packer:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":memshell:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":generator:publishAllPublicationsToMavenCentralRepository")
    } else {
        dependsOn(":memshell-party-common:publishAndReleaseToMavenCentral")
        dependsOn(":packer:publishAndReleaseToMavenCentral")
        dependsOn(":memshell:publishAndReleaseToMavenCentral")
        dependsOn(":generator:publishAndReleaseToMavenCentral")
    }
}
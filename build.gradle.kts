plugins {
    id("java")
}
version = "1.10.0-SNAPSHOT"

tasks.register("publishAllToMavenCentral") {
    val isSnapshot = rootProject.version.toString().endsWith("-SNAPSHOT")
    if (isSnapshot) {
        dependsOn(":memshell-party-bom:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":memshell-party-common:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":deserialize:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":memshell:publishAllPublicationsToMavenCentralRepository")
        dependsOn(":generator:publishAllPublicationsToMavenCentralRepository")
    } else {
        dependsOn(":memshell-party-bom:publishAndReleaseToMavenCentral")
        dependsOn(":memshell-party-common:publishAndReleaseToMavenCentral")
        dependsOn(":deserialize:publishAndReleaseToMavenCentral")
        dependsOn(":memshell:publishAndReleaseToMavenCentral")
        dependsOn(":generator:publishAndReleaseToMavenCentral")
    }
}
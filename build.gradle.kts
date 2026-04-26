plugins {
    id("java")
    id("idea")
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "2.6.2-SNAPSHOT"

tasks.register("publishAllToMavenCentral") {
    dependsOn(":memshell-party-common:publishToMavenCentral")
    dependsOn(":packer:publishToMavenCentral")
    dependsOn(":generator:publishToMavenCentral")
}

tasks.register("publishAllToMavenLocal") {
    dependsOn(":memshell-party-common:publishToMavenLocal")
    dependsOn(":packer:publishToMavenLocal")
    dependsOn(":generator:publishToMavenLocal")
}
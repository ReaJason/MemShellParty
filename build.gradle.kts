plugins {
    id("java")
    id("idea")
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "2.4.1"

tasks.register("publishAllToMavenCentral") {
    dependsOn(":memshell-party-common:publishToMavenCentral")
    dependsOn(":packer:publishToMavenCentral")
    dependsOn(":generator:publishToMavenCentral")
}
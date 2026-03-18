plugins {
    id("java")
    id("idea")
    id("com.vanniktech.maven.publish") version "0.35.0" apply false
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "2.7.0-SNAPSHOT"

tasks.register("publishAllToMavenCentral") {
    dependsOn(":memshell-party-common:publishToMavenCentral")
    dependsOn(":packer:publishToMavenCentral")
    dependsOn(":generator:publishToMavenCentral")
    dependsOn(":thirdparty:thirdparty-tomcat:publishToMavenCentral")
}

tasks.register("publishAllToMavenLocal") {
    dependsOn(":memshell-party-common:publishToMavenLocal")
    dependsOn(":packer:publishToMavenLocal")
    dependsOn(":generator:publishToMavenLocal")
    dependsOn(":thirdparty:thirdparty-tomcat:publishToMavenLocal")
}

plugins {
    id("java")
    id("idea")
    // apply false so all subprojects share one classloader for this plugin,
    // otherwise MavenCentralBuildService class identity differs across sibling projects
    id("com.vanniktech.maven.publish") version "0.35.0" apply false
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "3.0.0-SNAPSHOT"

tasks.register("publishAllToMavenCentral") {
    group = "publishing"
    description = "Publishes every module that applies the maven-publish-convention"
    // Discovered rather than hand-listed: the release must ship the provider modules too, since
    // the aggregate -server-all/-shelltool-all POMs reference them. A new provider module that
    // applies the convention is therefore picked up automatically.
    // The loop runs when this task is configured (task graph time) because the vanniktech
    // plugin registers publishToMavenCentral only during the subproject's afterEvaluate.
    subprojects.forEach { sub ->
        sub.plugins.withId("com.vanniktech.maven.publish") {
            dependsOn("${sub.path}:publishToMavenCentral")
        }
    }
}

tasks.register("publishAllToMavenLocal") {
    group = "publishing"
    description = "Publishes every module that applies the maven-publish-convention to mavenLocal"
    subprojects.forEach { sub ->
        sub.plugins.withId("com.vanniktech.maven.publish") {
            dependsOn("${sub.path}:publishToMavenLocal")
        }
    }
}
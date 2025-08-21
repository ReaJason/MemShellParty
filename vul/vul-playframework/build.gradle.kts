import play.gradle.plugin.PlayPlugin

plugins {
    id("org.playframework.play") version "3.1.0-M2"
    id("org.playframework.twirl") version "2.0.9"
}

val scalaVersion = System.getProperty("scala.version", PlayPlugin.DEFAULT_SCALA_VERSION).trimEnd { !it.isDigit() }

dependencies {
    implementation(platform("org.playframework:play-bom_$scalaVersion:3.0.8"))

//    implementation("org.playframework:play-pekko-http-server_$scalaVersion")
    implementation("org.playframework:play-netty-server_$scalaVersion")

    implementation("org.playframework:play-guice_$scalaVersion")
    implementation("org.playframework:play-java-forms_$scalaVersion")
    implementation("org.playframework:play-logback_$scalaVersion")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.playframework:play-test_$scalaVersion")
}

tasks.withType<ScalaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Xlint:deprecation", "-Werror"))
}
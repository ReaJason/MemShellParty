plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Aggregate module that includes all built-in server providers"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-server:memshell-party-server-tomcat"))
    api(project(":memshell-party-server:memshell-party-server-jetty"))
    api(project(":memshell-party-server:memshell-party-server-jetty5"))
    api(project(":memshell-party-server:memshell-party-server-undertow"))
    api(project(":memshell-party-server:memshell-party-server-jboss"))
    api(project(":memshell-party-server:memshell-party-server-resin"))
    api(project(":memshell-party-server:memshell-party-server-resin2"))
    api(project(":memshell-party-server:memshell-party-server-weblogic"))
    api(project(":memshell-party-server:memshell-party-server-websphere"))
    api(project(":memshell-party-server:memshell-party-server-glassfish"))
    api(project(":memshell-party-server:memshell-party-server-tongweb"))
    api(project(":memshell-party-server:memshell-party-server-bes"))
    api(project(":memshell-party-server:memshell-party-server-inforsuite"))
    api(project(":memshell-party-server:memshell-party-server-apusic"))
    api(project(":memshell-party-server:memshell-party-server-spring-webmvc"))
    api(project(":memshell-party-server:memshell-party-server-spring-webflux"))
    api(project(":memshell-party-server:memshell-party-server-xxljob"))
    api(project(":memshell-party-server:memshell-party-server-struts2"))
    api(project(":memshell-party-server:memshell-party-server-dubbo"))
}

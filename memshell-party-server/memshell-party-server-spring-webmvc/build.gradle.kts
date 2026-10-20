plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty SpringWebMvc server support"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // 生成期只按字节解析模板父类链，spring-webmvc 本身之外的 Spring 运行时依赖
    // （IoC/AOP/SpEL/JCL）不会在生成或运行时被用到，别让它们跟着 fat jar 发出去
    implementation(libs.spring.webmvc) {
        exclude(group = "org.springframework", module = "spring-beans")
        exclude(group = "org.springframework", module = "spring-context")
        exclude(group = "org.springframework", module = "spring-aop")
        exclude(group = "org.springframework", module = "spring-expression")
        exclude(group = "org.springframework", module = "spring-jcl")
    }
    implementation(libs.javax.servlet.api)
}

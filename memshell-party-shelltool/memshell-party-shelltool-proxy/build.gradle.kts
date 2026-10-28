plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Proxy shell tool"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-core"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // ProxyNettyHandler: io.netty.*
    compileOnly(libs.netty.all)
    // ProxyJettyHandler/Customizer: org.eclipse.jetty.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-jetty"))
    // ProxyValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // ProxyWebFilter/HandlerMethod/HandlerFunction: Spring WebFlux + Reactor
    compileOnly(libs.spring.webflux)
    // ProxyInterceptor/ControllerHandler: Spring MVC
    compileOnly(libs.spring.webmvc)
    // ProxyRawWebSocket: 仅依赖 Servlet 3.1+，不使用 javax.websocket
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    // ProxyWebSocket: javax.websocket.*（WebLogic 通过 ServerContainer 注册端点）
    compileOnly(libs.javax.websocket.api)
    testImplementation(project(":memshell-party-server:memshell-party-server-tomcat")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    testImplementation(project(":memshell-party-server:memshell-party-server-jetty")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-jetty")
    }
    testImplementation(project(":memshell-party-server:memshell-party-server-spring-webflux"))
    testImplementation(libs.junit.jupiter)
    // 真实容器/传输实现必须排在编译期桩前。
    testImplementation(libs.tomcat.embed.core)
    testImplementation("org.eclipse.jetty:jetty-server:12.0.16")
    testImplementation(libs.spring.webflux)
    testImplementation(libs.spring.context)
    testImplementation("io.projectreactor.netty:reactor-netty-http:1.1.25")
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.jakarta.servlet.api)
    testImplementation(libs.javax.websocket.api)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.13")
}

tasks.test {
    useJUnitPlatform()
    exclude("**/ProxyJetty12HandlerTest*")
}

val jetty12Test = tasks.register<Test>("jetty12Test") {
    description = "Runs the Jetty 12 transport test on its required JDK."
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    javaLauncher = javaToolchains.launcherFor {
        languageVersion = JavaLanguageVersion.of(17)
    }
    useJUnitPlatform()
    include("**/ProxyJetty12HandlerTest*")
}

tasks.check {
    dependsOn(jetty12Test)
}

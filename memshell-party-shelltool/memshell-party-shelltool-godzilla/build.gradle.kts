plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Godzilla shell tool"
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
    // GodzillaNettyHandler: io.netty.*（此前经 dubbo 传递解析，现显式声明）
    compileOnly(libs.netty.all)
    // GodzillaJettyHandler/Customizer: org.eclipse.jetty.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-jetty"))
    // GodzillaValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // GodzillaWebSocket: javax.websocket.*
    compileOnly(libs.javax.websocket.api)
    // GodzillaWebFilter/HandlerMethod/HandlerFunction: org.springframework.web.server.*/reactor（spring-web 由 webmvc 传递）
    compileOnly(libs.spring.webflux)
    // GodzillaInterceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    // 排除 Tomcat 桩：测试已用真 tomcat-embed-core 提供 catalina 签名，桩与它同包名，
    // 留在类路径上只会遮蔽真身（boot 上表现为 NoSuchMethodError: Adapter.getDomain()）
    testImplementation(project(":memshell-party-server:memshell-party-server-tomcat")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.tomcat.embed.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

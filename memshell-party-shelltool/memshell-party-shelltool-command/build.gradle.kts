plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Command shell tool"
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
    // CommandNettyHandler: io.netty.*（此前经 dubbo 传递解析，现显式声明）
    compileOnly(libs.netty.all)
    // CommandJettyHandler/Customizer: org.eclipse.jetty.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-jetty"))
    // CommandUpgrade: org.apache.coyote.*/org.apache.tomcat.util.net.*；CommandValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // CommandWebSocket: javax.websocket.*（WebLogic 通过 ServerContainer 注册端点）
    compileOnly(libs.javax.websocket.api)
    // CommandRawWebSocket: 仅依赖 Servlet 3.1+，不使用 javax.websocket
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    // CommandWebFilter/HandlerFunction: org.springframework.web.server.*/reactor（spring-web 由 webmvc 传递）
    compileOnly(libs.spring.webflux)
    // CommandInterceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    testImplementation(project(":memshell-party-packer"))
    // 排除 Tomcat 桩：测试已用真 tomcat-embed-core 提供 catalina/coyote 签名，桩与它同包名，
    // 留在类路径上只会遮蔽真身（boot 上表现为 NoSuchMethodError: Adapter.getDomain()）
    testImplementation(project(":memshell-party-server:memshell-party-server-tomcat")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    testImplementation(project(":memshell-party-stub:memshell-party-stub-jetty"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.tomcat.embed.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

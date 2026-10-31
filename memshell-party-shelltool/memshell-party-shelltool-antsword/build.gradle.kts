plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty AntSword shell tool"

dependencies {
    api(project(":memshell-party-core"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // AntSwordValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // AntSwordInterceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

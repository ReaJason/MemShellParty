plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty Suo5 shell tool"

dependencies {
    api(project(":memshell-party-core"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // Suo5JettyHandler/Customizer: org.eclipse.jetty.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-jetty"))
    // Suo5Valve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // Suo5Interceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    // Suo5WebFilter: reactor.netty.*（WebFilter 类本身在 spring-web 中，由 webmvc 传递）
    compileOnly(libs.reactor.netty.core)
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
}

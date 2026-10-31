plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty Jetty server support"

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    implementation(libs.javax.servlet.api)
    // Jetty 模板父类（org.eclipse.jetty.server.Handler 等）的编译期桩：生成期按字节解析
    // 模板父链时需要它在运行时类路径上（不会加载进 JVM），随本模块一起走
    implementation(project(":memshell-party-stub:memshell-party-stub-jetty"))
}

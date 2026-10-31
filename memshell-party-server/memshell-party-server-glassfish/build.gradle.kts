plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty GlassFish server support"

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    api(project(":memshell-party-server:memshell-party-server-tomcat"))
    implementation(libs.javax.servlet.api)
}

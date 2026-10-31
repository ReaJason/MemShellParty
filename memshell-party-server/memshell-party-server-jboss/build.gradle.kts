plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty Jboss server support"

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    api(project(":memshell-party-server:memshell-party-server-tomcat"))
    api(project(":memshell-party-server:memshell-party-server-glassfish"))
    implementation(libs.javax.servlet.api)
}

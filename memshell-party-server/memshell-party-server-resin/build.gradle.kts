plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty Resin server support"

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    implementation(libs.javax.servlet.api)
}

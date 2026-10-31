plugins {
    id("java8-library-conventions")
}

description = "Jetty compile-time stubs for MemShellParty shell templates (compileOnly only, never ship at runtime)"

dependencies {
    compileOnly(libs.javax.servlet.api)
}

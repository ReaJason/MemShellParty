plugins {
    id("java8-library-conventions")
}

description = "Aggregate module that includes all built-in shell tool providers"

dependencies {
    api(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-behinder"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-command"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-suo5"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-antsword"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-neoregeorg"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-proxy"))
}

package io.github.reajason.dubbo.fixture.client;

public final class ClientRuntimeSupport {

    private static final String[] PROXY_PROPERTIES = new String[]{
            "proxyHost",
            "proxyPort",
            "http.proxyHost",
            "http.proxyPort",
            "https.proxyHost",
            "https.proxyPort",
            "socksProxyHost",
            "socksProxyPort",
            "ftp.proxyHost",
            "ftp.proxyPort"
    };

    private ClientRuntimeSupport() {
    }

    public static void prepareClientJvm() {
        System.setProperty("dubbo.compiler", "jdk");
        System.setProperty("java.net.preferIPv4Stack", "true");
        System.setProperty("java.net.useSystemProxies", "false");
        for (String property : PROXY_PROPERTIES) {
            System.clearProperty(property);
        }
    }
}

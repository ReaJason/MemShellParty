package com.reajason.javaweb.utils;

import lombok.SneakyThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.reajason.javaweb.Server.*;

/**
 * @author ReaJason
 */
public class CommonUtil {

    public static final String[] INJECTOR_CLASS_NAMES = new String[]{"SignatureUtils", "NetworkUtils", "KeyUtils", "EncryptionUtils", "SessionDataUtil", "SOAPUtils", "ReflectUtil", "HttpClientUtil", "EncryptionUtil", "XMLUtil", "JSONUtil", "FileUtils", "DateUtil", "StringUtil", "MathUtil", "HttpUtil", "CSVUtil", "ImageUtil", "ThreadUtil", "ReportUtil", "EncodingUtil", "ConfigurationUtil", "HTMLUtil", "SerializationUtil"};
    public static final Set<String> JAVA_KEYWORDS = new HashSet<>(Arrays.asList("abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
            "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
            "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
            "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super",
            "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while"));
    private static final String[] PACKAGE_NAMES = {
            "org.springframework",
            "org.apache.commons",
            "org.apache.logging",
            "org.apache",
            "com.fasterxml.jackson",
            "org.junit",
            "org.apache.commons.lang",
            "org.apache.http.client",
            "com.google.gso",
            "ch.qos.logback"
    };
    private static final String[] MIDDLEWARE_NAMES = {
            "Error",
            "Log",
            "Report",
            "Auth",
            "OAuth",
            "Checker"
    };

    @SneakyThrows
    public static byte[] gzipCompress(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }

    @SneakyThrows
    public static byte[] gzipDecompress(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = gzip.read(buffer)) != -1) {
                out.write(buffer, 0, length);

            }
        }
        return out.toByteArray();
    }

    public static String getRandomString(int length) {
        String randomString = getRandomStringInternal(length);
        while (JAVA_KEYWORDS.contains(randomString)) {
            randomString = getRandomStringInternal(length);
        }
        return randomString;
    }

    private static String getRandomStringInternal(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(52);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static String getRandomPackageName() {
        return PACKAGE_NAMES[new Random().nextInt(PACKAGE_NAMES.length)] + "." + getRandomString(5);
    }

    public static String getPackageName(String className) {
        return className.substring(0, className.lastIndexOf("."));
    }

    public static String generateClassName() {
        String randomString = getRandomString(5);
        return getRandomPackageName() + ".Error" + randomString.substring(0, 1).toUpperCase() + randomString.substring(1).toLowerCase() + "Handler";
    }

    public static String generateInjectorClassName() {
        return getRandomPackageName() + "." + INJECTOR_CLASS_NAMES[new Random().nextInt(INJECTOR_CLASS_NAMES.length)];
    }

    public static String appendLambdaSuffix(String className) {
        if (className.contains("$Lambda$")) {
            return className;
        }
        return className + "$Proxy0$$Lambda$1";
    }

    public static String getWebPackageNameForServer(String server) {
        switch (server) {
            case Jetty:
                return "org.eclipse.jetty.servlet.handlers";
            case Undertow:
                return "io.undertow.servlet.handlers";
            case SpringWebMvc:
                return "org.springframework.boot.mvc.handlers";
            case SpringWebFlux:
                return "org.springframework.boot.webflux.handlers";
            case WebSphere:
                return "com.ibm.ws.webcontainer.handlers";
            case WebLogic:
                return "weblogic.servlet.internal.handlers";
            case Resin:
                return "com.caucho.server.dispatch.handlers";
            case BES:
                return "com.bes.enterprise.webtier.web.handlers";
            case Apusic:
                return "com.apusic.web.handlers";
            case InforSuite:
                return "com.cvicse.inforsuite.web.handlers";
            default:
                return "org.apache.http.web.handlers";
        }
    }

    public static String generateShellClassName(String server, String shellType) {
        return getWebPackageNameForServer(server)
                + "." + getRandomString(5)
                + "." + MIDDLEWARE_NAMES[new Random().nextInt(MIDDLEWARE_NAMES.length)] + shellType;
    }

    public static String getSimpleName(String injectorClassName) {
        return injectorClassName.substring(injectorClassName.lastIndexOf(".") + 1);
    }
}
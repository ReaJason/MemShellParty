package com.reajason.javaweb.memshell.shelltool.proxy;

import com.sun.net.httpserver.HttpServer;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassUtils;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyHttpEmbeddedTomcatTest {

    @TempDir
    Path baseDir;

    @Test
    void generatedServletForwardsHttpConnectOverPht() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), this::verifyTunnel);
    }

    private void verifyTunnel() throws Exception {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        target.createContext("/", exchange -> {
            byte[] body = "pht-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        target.start();

        Path webapp = Files.createDirectories(baseDir.resolve("webapp"));
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.resolve("tomcat").toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        Context context = tomcat.addWebapp("", webapp.toString());
        ProxyConfig toolConfig = ProxyConfig.builder()
                .shellTemplateClassName(ProxyServlet.class.getName())
                .shellClassName("org.apache.utils.GeneratedProxyServlet")
                .headerName(ProxyPhtTestSupport.HEADER_NAME)
                .headerValue(ProxyPhtTestSupport.HEADER_VALUE)
                .build();
        byte[] shellBytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.SERVLET)
                .build(), toolConfig).getBytes();
        Servlet shell = (Servlet) ClassUtils.newInstance(shellBytes);
        Tomcat.addServlet(context, "proxy", shell).addMapping("/proxy");
        tomcat.start();

        String endpoint = "http://127.0.0.1:" + tomcat.getConnector().getLocalPort() + "/proxy";
        HttpURLConnection pull = null;
        try {
            HttpURLConnection authorize = connection(endpoint + "?token=", "GET");
            assertEquals(200, authorize.getResponseCode());
            String authorization = new String(readAll(authorize.getInputStream()), StandardCharsets.US_ASCII);
            assertTrue(authorization.startsWith("token="));
            String token = authorization.substring("token=".length());

            pull = connection(endpoint + "?token=" + token, "GET");
            pull.setReadTimeout(15000);
            assertEquals(200, pull.getResponseCode());
            BufferedReader pullReader = new BufferedReader(new InputStreamReader(
                    pull.getInputStream(), StandardCharsets.US_ASCII));

            String connect = "CONNECT 127.0.0.1:" + target.getAddress().getPort() + " HTTP/1.1\r\n\r\n";
            push(endpoint, token, connect.getBytes(StandardCharsets.ISO_8859_1));
            String established = new String(Base64.getDecoder().decode(pullReader.readLine()),
                    StandardCharsets.ISO_8859_1);
            assertEquals("HTTP/1.1 200 Connection Established\r\n\r\n", established);

            String request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            push(endpoint, token, request.getBytes(StandardCharsets.ISO_8859_1));
            ByteArrayOutputStream targetResponse = new ByteArrayOutputStream();
            String line;
            while ((line = pullReader.readLine()) != null) {
                if (!line.isEmpty()) {
                    byte[] data = Base64.getDecoder().decode(line);
                    targetResponse.write(data);
                }
            }
            String response = new String(targetResponse.toByteArray(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertTrue(response.endsWith("pht-ok"), response);
            assertNull(pullReader.readLine());
        } finally {
            if (pull != null) {
                pull.disconnect();
            }
            tomcat.stop();
            tomcat.destroy();
            target.stop(0);
        }
    }

    @Test
    void generatedFiltersKeepSessionsIsolatedByHeader() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), this::verifyFilterIsolation);
    }

    private void verifyFilterIsolation() throws Exception {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        target.createContext("/", exchange -> {
            byte[] body = "pht-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        target.start();

        Path webapp = Files.createDirectories(baseDir.resolve("isolated-webapp"));
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.resolve("isolated-tomcat").toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        Context context = tomcat.addWebapp("", webapp.toString());
        Filter first = generateFilter("First", "first-secret");
        Filter second = generateFilter("Second", "second-secret");
        addFilter(context, "first", first);
        addFilter(context, "second", second);
        tomcat.start();

        try {
            Class<?> firstCore = proxyHttpCore(first);
            Class<?> secondCore = proxyHttpCore(second);
            String token = UUID.randomUUID().toString();
            assertNull(firstCore.getMethod("getSession", String.class).invoke(null, token));
            assertNull(secondCore.getMethod("getSession", String.class).invoke(null, token));

            String endpoint = "http://127.0.0.1:" + tomcat.getConnector().getLocalPort() + "/proxy";
            ProxyPhtTestSupport.verifyTunnelSession(endpoint, target.getAddress().getPort(), token,
                    false, ProxyPhtTestSupport.HEADER_NAME, "second-secret");
            assertNull(firstCore.getMethod("getSession", String.class).invoke(null, token));
            assertNotNull(secondCore.getMethod("getSession", String.class).invoke(null, token));
        } finally {
            tomcat.stop();
            tomcat.destroy();
            target.stop(0);
        }
    }

    private static Filter generateFilter(String suffix, String headerValue) {
        ProxyConfig config = ProxyConfig.builder()
                .shellTemplateClassName(ProxyFilter.class.getName())
                .shellClassName("org.apache.utils.GeneratedProxyFilter" + suffix)
                .headerName(ProxyPhtTestSupport.HEADER_NAME)
                .headerValue(headerValue)
                .build();
        byte[] bytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .build(), config).getBytes();
        return (Filter) ClassUtils.newInstance(bytes);
    }

    private static void addFilter(Context context, String name, Filter filter) {
        FilterDef definition = new FilterDef();
        definition.setFilterName(name);
        definition.setFilter(filter);
        context.addFilterDef(definition);
        FilterMap mapping = new FilterMap();
        mapping.setFilterName(name);
        mapping.addURLPattern("/*");
        context.addFilterMapBefore(mapping);
    }

    private static Class<?> proxyHttpCore(Filter filter) throws Exception {
        Method method = filter.getClass().getDeclaredMethod("getProxyHttpClass");
        method.setAccessible(true);
        return (Class<?>) method.invoke(null);
    }

    private static void push(String endpoint, String token, byte[] data) throws IOException {
        byte[] body = Base64.getEncoder().encode(data);
        HttpURLConnection connection = connection(endpoint + "?token=" + token, "POST");
        connection.setFixedLengthStreamingMode(body.length);
        connection.setDoOutput(true);
        OutputStream output = connection.getOutputStream();
        output.write(body);
        output.flush();
        assertEquals(200, connection.getResponseCode());
        connection.disconnect();
    }

    private static HttpURLConnection connection(String url, String method) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty(ProxyPhtTestSupport.HEADER_NAME, ProxyPhtTestSupport.HEADER_VALUE);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(15000);
        return connection;
    }

    private static byte[] readAll(InputStream input) throws IOException {
        assertNotNull(input);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }
}

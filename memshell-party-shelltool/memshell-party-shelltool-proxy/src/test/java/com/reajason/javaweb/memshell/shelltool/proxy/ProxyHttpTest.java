package com.reajason.javaweb.memshell.shelltool.proxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ProxyHttpTest {

    @BeforeEach
    void configureHeaders() {
        ProxyHttp.headerName = ProxyPhtTestSupport.HEADER_NAME;
        ProxyHttp.headerValue = ProxyPhtTestSupport.HEADER_VALUE;
    }

    @Test
    void ordinaryRequestIsNotClaimed() {
        Object request = request("GET", null, false);
        Object response = response(new AtomicInteger());
        assertFalse(new ProxyHttp().equals(new Object[]{request, response}));
    }

    @Test
    void requestWithMissingOrDifferentHeaderIsNotClaimed() {
        AtomicInteger status = new AtomicInteger();
        Object response = response(status);
        String query = "token=" + token();

        assertFalse(new ProxyHttp().equals(new Object[]{
                request("POST", query, false, null), response}));
        assertFalse(new ProxyHttp().equals(new Object[]{
                request("POST", query, false, "different"), response}));
        assertEquals(0, status.get());
    }

    @Test
    void recognizedFailureDoesNotFallThrough() throws Exception {
        String token = ProxyHttp.createSession();
        assertNotNull(token);
        AtomicInteger status = new AtomicInteger();
        Object request = request("POST", "token=" + token, true);
        Object response = response(status);

        assertTrue(new ProxyHttp().equals(new Object[]{request, response}));
        assertEquals(500, status.get());
        assertTrue(ProxyHttp.getSession(token).isClosed());
    }

    @ParameterizedTest
    @MethodSource("invalidHandshakes")
    void invalidHandshakeReturnsErrorAndEnds(String handshake, String status) throws Exception {
        ProxyHttp session = newSession();
        session.write(handshake.getBytes(StandardCharsets.ISO_8859_1));

        assertEquals("HTTP/1.1 " + status + "\r\n\r\n",
                new String(session.poll(), StandardCharsets.ISO_8859_1));
        assertEquals(0, session.poll().length);
        assertTrue(session.isClosed());
    }

    static Stream<Arguments> invalidHandshakes() {
        return Stream.of(
                arguments("GET / HTTP/1.1\r\n\r\n", "400 Bad Request"),
                arguments("CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n", "400 Bad Request"),
                arguments("CONNECT 127.0.0.1:not-a-port HTTP/1.1\r\n\r\n", "400 Bad Request"),
                arguments("CONNECT ::1:8080 HTTP/1.1\r\n\r\n", "400 Bad Request"),
                arguments("CONNECT 127.0.0.1:8080 HTTP/1.1\r\nX-Gost-Protocol: udp\r\n\r\n",
                        "501 Not Implemented")
        );
    }

    @Test
    void closedSessionsDoNotConsumeActiveCapacity() {
        for (int i = 0; i < 128; i++) {
            String token = ProxyHttp.createSession();
            assertNotNull(token);
            ProxyHttp.getSession(token).close();
        }
        String token = ProxyHttp.createSession();
        assertNotNull(token);
        ProxyHttp.getSession(token).close();
    }

    @Test
    void unknownTokensDoNotConsumeActiveCapacity() {
        for (int i = 0; i < 128; i++) {
            assertNull(ProxyHttp.getSession(token()));
        }
        String token = ProxyHttp.createSession();
        assertNotNull(token);
        ProxyHttp.getSession(token).close();
    }

    @Test
    void clientProvidedTokenCreatesOneSharedSession() {
        String token = token();
        ProxyHttp session = ProxyHttp.getOrCreateSession(token);
        assertNotNull(session);
        assertSame(session, ProxyHttp.getOrCreateSession(token));
        assertSame(session, ProxyHttp.getSession(token));
        session.close();
    }

    @Test
    void onlyOnePullCanBeActive() {
        ProxyHttp session = newSession();
        assertTrue(session.beginPull());
        assertFalse(session.beginPull());
        session.endPull();
        assertTrue(session.beginPull());
        session.endPull();
        session.close();
    }

    private static ProxyHttp newSession() {
        String token = ProxyHttp.createSession();
        assertNotNull(token);
        return ProxyHttp.getSession(token);
    }

    private static String token() {
        return UUID.randomUUID().toString();
    }

    private static Object request(String method, String query, boolean failBody) {
        return request(method, query, failBody, ProxyPhtTestSupport.HEADER_VALUE);
    }

    private static Object request(String method, String query, boolean failBody, String header) {
        InvocationHandler handler = (proxy, invoked, args) -> {
            if ("getMethod".equals(invoked.getName())) {
                return method;
            }
            if ("getQueryString".equals(invoked.getName())) {
                return query;
            }
            if ("getHeader".equals(invoked.getName()) && ProxyPhtTestSupport.HEADER_NAME.equals(args[0])) {
                return header;
            }
            if ("getInputStream".equals(invoked.getName()) && failBody) {
                throw new IOException("request body failed");
            }
            return defaultValue(invoked);
        };
        return Proxy.newProxyInstance(ProxyHttpTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, handler);
    }

    private static Object response(AtomicInteger status) {
        InvocationHandler handler = (proxy, invoked, args) -> {
            if ("setStatus".equals(invoked.getName())) {
                status.set((Integer) args[0]);
            }
            return defaultValue(invoked);
        };
        return Proxy.newProxyInstance(ProxyHttpTest.class.getClassLoader(),
                new Class<?>[]{HttpServletResponse.class}, handler);
    }

    private static Object defaultValue(Method method) {
        Class<?> type = method.getReturnType();
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }
}

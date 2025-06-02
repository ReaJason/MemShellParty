package com.reajason.javaweb.memshell.shelltool;

import lombok.SneakyThrows;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletException;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * @author ReaJason
 * @since 2025/6/2
 */
public class ProxyTest {

    static class ValveProxy implements InvocationHandler {

        private final Valve valve;

        ValveProxy(Valve valve) {
            this.valve = valve;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            System.out.println("hello world" + method.getName());
            return method.invoke(valve, args);
        }
    }

    static class TestValve implements Valve {

        @Override
        public Valve getNext() {
            return null;
        }

        @Override
        public void setNext(Valve valve) {

        }

        @Override
        public void backgroundProcess() {

        }

        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            System.out.println("invoke method");
        }

        @Override
        public boolean isAsyncSupported() {
            return false;
        }
    }

    @Test
    @SneakyThrows
    void test() {
        Valve valve = (Valve) Proxy.newProxyInstance(this.getClass().getClassLoader(), new Class[]{Valve.class}, new ValveProxy(new TestValve()));
        valve.invoke(null, null);
    }
}

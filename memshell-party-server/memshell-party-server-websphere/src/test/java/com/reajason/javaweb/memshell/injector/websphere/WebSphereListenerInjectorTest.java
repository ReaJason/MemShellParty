package com.reajason.javaweb.memshell.injector.websphere;

import com.ibm.ws.webcontainer.managedobject.ManagedObjectListenerWrapper;
import com.ibm.ws.webcontainer.webapp.WebApp;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EventListener;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class WebSphereListenerInjectorTest {

    @Test
    void wrapsListenerAndDetectsDuplicateThroughWrapper() throws Exception {
        TestContext context = new TestContext();
        TestListener listener = new TestListener();
        WebSphereListenerInjector injector = new WebSphereListenerInjector() {
            @Override
            public String getClassName() {
                return TestListener.class.getName();
            }
        };

        injector.inject(context, listener);

        assertEquals(1, context.servletRequestListeners.size());
        Object entry = context.servletRequestListeners.get(0);
        ManagedObjectListenerWrapper wrapper = assertInstanceOf(ManagedObjectListenerWrapper.class, entry);
        assertSame(listener, wrapper.getListener());
        assertSame(context, wrapper.getWebApp());

        injector.inject(context, new TestListener());
        assertEquals(1, context.servletRequestListeners.size());
    }

    private static class TestContext extends WebApp {
        private final List<Object> servletRequestListeners = new ArrayList<>();
    }

    private static class TestListener implements EventListener {
    }
}

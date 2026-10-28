package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilelessAgentBootstrapJarTest {

    @AfterEach
    void clearFixtureState() {
        System.clearProperty(JarAgentFixture.Agent.INIT_PROPERTY);
    }

    @Test
    void installsAgentAndResourcesDirectlyFromRawJarBytes() throws Exception {
        byte[] jarBytes = agentJar();
        Instrumentation instrumentation = FilelessAgentBootstrapTest.instrumentation(true, true);

        ClassLoader loader = FilelessAgentBootstrap.install(jarBytes, "memory-agent-args", instrumentation, null);
        Class<?> agent = loader.loadClass(JarAgentFixture.Agent.class.getName());

        assertTrue(loader instanceof JarLoader);
        assertSame(loader, agent.getClassLoader());
        assertEquals("memory-agent-args", agent.getField("args").get(null));
        assertEquals("memory-resource", agent.getField("resource").get(null));
        assertSame(instrumentation, agent.getField("instrumentation").get(null));
        assertSame(loader, agent.getField("contextClassLoader").get(null));
    }

    @Test
    void exposesManifestThroughSingularAndPluralResourceLookup() throws Exception {
        JarLoader loader = new JarLoader(agentJar(), null);

        URL manifest = loader.getResource("META-INF/MANIFEST.MF");
        assertNotNull(manifest);
        assertEquals("1", readManifest(manifest).getMainAttributes().getValue("Fileless-Agent-Contract"));

        Enumeration<URL> manifests = loader.getResources("META-INF/MANIFEST.MF");
        assertTrue(manifests.hasMoreElements());
        assertEquals("1", readManifest(manifests.nextElement()).getMainAttributes()
                .getValue("Fileless-Agent-Contract"));
        assertFalse(manifests.hasMoreElements());
    }

    @Test
    void capabilityFailureDoesNotInitializeAgentFromJar() {
        System.clearProperty(JarAgentFixture.Agent.INIT_PROPERTY);
        Instrumentation instrumentation = FilelessAgentBootstrapTest.instrumentation(true, false);

        assertThrows(UnsupportedOperationException.class, () -> FilelessAgentBootstrap.install(
                agentJar(), null, instrumentation, null));
        assertNull(System.getProperty(JarAgentFixture.Agent.INIT_PROPERTY));
    }

    private static Manifest readManifest(URL url) throws Exception {
        InputStream input = url.openStream();
        try {
            return new Manifest(input);
        } finally {
            input.close();
        }
    }

    private static byte[] agentJar() {
        try {
            Manifest manifest = new Manifest();
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
            manifest.getMainAttributes().putValue("Agent-Class", JarAgentFixture.Agent.class.getName());
            manifest.getMainAttributes().putValue("Fileless-Agent-Contract", "1");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            JarOutputStream output = new JarOutputStream(bytes, manifest);
            addEntry(output, JarAgentFixture.Agent.class.getName().replace('.', '/') + ".class",
                    readClass(JarAgentFixture.Agent.class));
            addEntry(output, "fixture/data.txt", "memory-resource".getBytes("UTF-8"));
            output.close();
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] readClass(Class<?> type) throws Exception {
        String resource = type.getName().replace('.', '/') + ".class";
        InputStream input = type.getClassLoader().getResourceAsStream(resource);
        if (input == null) {
            throw new IllegalStateException("Missing " + resource);
        }
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int length;
            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static void addEntry(JarOutputStream output, String name, byte[] bytes) throws Exception {
        output.putNextEntry(new JarEntry(name));
        output.write(bytes);
        output.closeEntry();
    }
}

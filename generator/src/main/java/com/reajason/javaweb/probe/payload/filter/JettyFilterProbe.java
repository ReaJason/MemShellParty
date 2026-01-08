package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class JettyFilterProbe {

    @Override
    public String toString() {
        String msg = "";
        Map<String, List<Map<String, String>>> allFiltersData = new LinkedHashMap<String, List<Map<String, String>>>();
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null || contexts.isEmpty()) {
            msg += "context not found\n";
        } else {
            for (Object context : contexts) {
                String contextRoot = getContextRoot(context);
                List<Map<String, String>> filters = collectFiltersData(context);
                allFiltersData.put(contextRoot, filters);
            }
            msg += formatFiltersData(allFiltersData);
        }
        return msg;
    }

    private List<Map<String, String>> collectFiltersData(Object context) {
        List<Map<String, String>> result = new ArrayList<>();
        try {
            Object servletHandler = getFieldValue(context, "_servletHandler");
            if (servletHandler == null) return Collections.emptyList();
            Object[] filterMappings = (Object[]) invokeMethod(servletHandler, "getFilterMappings");
            Object[] filterHolders = (Object[]) invokeMethod(servletHandler, "getFilters");
            if (filterMappings == null || filterMappings.length == 0) return Collections.emptyList();
            for (Object mapping : filterMappings) {
                String name = (String) invokeMethod(mapping, "getFilterName");
                if (name == null) continue;
                String filterClass = "N/A";
                if (filterHolders != null) {
                    for (Object holder : filterHolders) {
                        String holderName = (String) invokeMethod(holder, "getName");
                        if (!name.equals(holderName)) continue;
                        String cls = (String) invokeMethod(holder, "getClassName");
                        if (cls == null) {
                            Object filterInstance = invokeMethod(holder, "getFilter");
                            if (filterInstance != null) {
                                cls = filterInstance.getClass().getName();
                            }
                        }

                        if (cls != null) filterClass = cls;
                        break;
                    }
                }
                Map<String, String> info = new HashMap<>();
                info.put("filterName", name);
                info.put("filterClass", filterClass);
                try {
                    String[] pathSpecs = (String[]) invokeMethod(mapping, "getPathSpecs");
                    info.put("urlPatterns", pathSpecs.length == 0 ? "" : Arrays.toString(pathSpecs));
                } catch (Exception ignored) {
                }
                result.add(info);
            }
        } catch (Exception ignored) {
        }
        return result;
    }

    @SuppressWarnings("all")
    private String formatFiltersData(Map<String, List<Map<String, String>>> allFiltersData) {
        StringBuilder output = new StringBuilder();
        for (Map.Entry<String, List<Map<String, String>>> entry : allFiltersData.entrySet()) {
            String context = entry.getKey();
            List<Map<String, String>> filters = entry.getValue();
            output.append("Context: ").append(context).append("\n");
            if (filters.isEmpty()) {
                output.append("No filters found\n");
            } else if (filters.size() == 1 && filters.get(0).containsKey("error")) {
                output.append(filters.get(0).get("error")).append("\n");
            } else {
                for (Map<String, String> info : filters) {
                    appendIfPresent(output, "", info.get("filterName"), "");
                    appendIfPresent(output, " -> ", info.get("filterClass"), "");
                    appendIfPresent(output, " -> URL:", info.get("urlPatterns"), "");
                    output.append("\n");
                }
            }
        }
        return output.toString();
    }

    private void appendIfPresent(StringBuilder sb, String prefix, String value, String suffix) {
        if (value != null && !value.isEmpty()) {
            sb.append(prefix).append(value).append(suffix);
        }
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(context, "getContextPath");
        } catch (Exception ignored) {
        }
        String c = context.getClass().getName();
        if (r == null) {
            return c;
        }
        if (r.isEmpty()) {
            return c + "(/)";
        }
        return c + "(" + r + ")";
    }

    /**
     * org.mortbay.jetty.webapp.WebAppContext
     * org.eclipse.jetty.webapp.WebAppContext
     * org.eclipse.jetty.ee8.webapp.WebAppContext
     * org.eclipse.jetty.ee9.webapp.WebAppContext
     * org.eclipse.jetty.ee10.webapp.WebAppContext
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                // jetty 6
                Object contextClassLoader = invokeMethod(thread, "getContextClassLoader");
                if (contextClassLoader.getClass().getName().contains("WebAppClassLoader")) {
                    contexts.add(getFieldValue(contextClassLoader, "_context"));
                } else {
                    // jetty 7+
                    Object table = getFieldValue(getFieldValue(thread, "threadLocals"), "table");
                    for (int i = 0; i < Array.getLength(table); i++) {
                        Object entry = Array.get(table, i);
                        if (entry != null) {
                            Object threadLocalValue = getFieldValue(entry, "value");
                            if (threadLocalValue != null) {
                                if (threadLocalValue.getClass().getName().contains("WebAppContext")) {
                                    contexts.add(getFieldValue(threadLocalValue, "this$0"));
                                }
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) {
        Class<?>[] paramClazz = null;
        Object[] param = null;
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    if (paramClazz == null) {
                        method = clazz.getDeclaredMethod(methodName);
                    } else {
                        method = clazz.getDeclaredMethod(methodName, paramClazz);
                    }
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                throw new NoSuchMethodException("Method not found: " + methodName);
            }

            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj, param);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }

    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}

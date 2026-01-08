package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class ResinFilterProbe {

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
            Object filterMapper = getFieldValue(context, "_filterMapper");
            Object filterManager = getFieldValue(context, "_filterManager");
            if (filterMapper == null) return Collections.emptyList();
            ArrayList<Object> filterMappings = (ArrayList<Object>) getFieldValue(filterMapper, "_filterMap");
            for (Object filterMapping : filterMappings) {
                Map<String, String> info = new HashMap<>();
                String filterName = (String) invokeMethod(filterMapping, "getFilterName", null, null);
                info.put("filterName", filterName);
                String filterClassName = (String) invokeMethod(filterMapping, "getFilterClassName", null, null);
                try {
                    if (filterClassName == null) {
                        Class<?> filterClass = (Class<?>) invokeMethod(filterMapping, "getFilterClass", null, null);
                        if (filterClass != null) {
                            filterClassName = filterClass.getName();
                        } else {
                            Object filter = ((Map<String, Object>) getFieldValue(filterManager, "_instances")).get(filterName);
                            if (filter != null) {
                                filterClassName = filter.getClass().getName();
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
                info.put("filterClass", filterClassName != null ? filterClassName : "N/A");

                List<String> urlPatterns = new ArrayList<>();
                String urlPattern = invokeMethod(filterMapping, "getURLPattern", null, null).toString();
                if (urlPattern == null || urlPattern.isEmpty()) {
                    List<Object> matchList = (List<Object>) getFieldValue(filterMapping, "_matchList");
                    if (matchList != null && !matchList.isEmpty()) {
                        for (Object match : matchList) {
                            if (((Integer) getFieldValue(match, "_value")) == 1) {
                                urlPatterns.add(getFieldValue(match, "_regex").toString());
                            }
                        }
                    }
                } else {
                    urlPatterns.add(urlPattern);
                }
                info.put("urlPatterns", Arrays.toString(urlPatterns.toArray()));
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
            r = (String) invokeMethod(context, "getContextPath", null, null);
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
     * com.caucho.server.webapp.Application
     * /usr/local/resin3/lib/resin.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            Class<?> servletInvocationClass = null;
            try {
                servletInvocationClass = thread.getContextClassLoader()
                        .loadClass("com.caucho.server.dispatch.ServletInvocation");
            } catch (Exception e) {
                continue;
            }
            if (servletInvocationClass != null) {
                Object contextRequest = servletInvocationClass.getMethod("getContextRequest").invoke(null);
                Object webApp = invokeMethod(contextRequest, "getWebApp", new Class[0], new Object[0]);
                contexts.add(webApp);
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
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

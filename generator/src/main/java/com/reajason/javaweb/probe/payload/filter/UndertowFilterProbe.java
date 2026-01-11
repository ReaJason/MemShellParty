package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class UndertowFilterProbe {

    @Override
    @SuppressWarnings("Duplicates")
    public String toString() {
        StringBuilder msg = new StringBuilder();
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg.append("context error: ").append(getErrorMessage(throwable));
        }
        if (contexts == null || contexts.isEmpty()) {
            msg.append("context not found\n");
        } else {
            Map<String, List<Map<String, String>>> allFiltersData = new LinkedHashMap<String, List<Map<String, String>>>();
            for (Object context : contexts) {
                String contextRoot = getContextRoot(context);
                try {
                    List<Map<String, String>> filters = collectFiltersData(context);
                    allFiltersData.put(contextRoot, filters);
                } catch (Throwable e) {
                    msg.append(contextRoot).append(" failed ").append(getErrorMessage(e)).append("\n");
                }
            }
            msg.append(formatFiltersData(allFiltersData));
        }
        return msg.toString();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, String>> collectFiltersData(Object context) throws Exception {
        // context -> io.undertow.servlet.spec.ServletContextImpl
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        // deploymentInfo -> io.undertow.servlet.api.DeploymentInfo
        Object deploymentInfo = getFieldValue(context, "deploymentInfo");
        Map<String, Object> filters = (Map<String, Object>) getFieldValue(deploymentInfo, "filters");
        List<Object> filterUrlMappings = (List<Object>) getFieldValue(deploymentInfo, "filterUrlMappings");
        List<Object> filterServletNameMappings = (List<Object>) getFieldValue(deploymentInfo, "filterServletNameMappings");
        for (Object filterUrlMapping : filterUrlMappings) {
            // filterUrlMapping -> io.undertow.servlet.api.FilterMappingInfo
            Map<String, Object> info = fillFilterInfo(filterUrlMapping, filters, aggregatedData);
            String urlPattern = (String) getFieldValue(filterUrlMapping, "mapping");
            if (urlPattern != null) {
                ((Set<String>) info.get("urlPatterns")).add(urlPattern);
            }
        }
        for (Object filterServletNameMapping : filterServletNameMappings) {
            // filterServletNameMapping -> io.undertow.servlet.api.FilterMappingInfo
            Map<String, Object> info = fillFilterInfo(filterServletNameMapping, filters, aggregatedData);
            String servletNames = (String) getFieldValue(filterServletNameMapping, "mapping");
            if (servletNames != null) {
                ((Set<String>) info.get("servletNames")).add(servletNames);
            }
        }
        List<Map<String, String>> result = new ArrayList<>();
        for (Map<String, Object> entry : aggregatedData.values()) {
            Map<String, String> finalInfo = new HashMap<>();
            finalInfo.put("filterName", (String) entry.get("filterName"));
            finalInfo.put("filterClass", (String) entry.get("filterClass"));
            Set<?> urls = (Set<?>) entry.get("urlPatterns");
            finalInfo.put("urlPatterns", urls.isEmpty() ? "" : urls.toString());
            Set<?> servletNames = (Set<?>) entry.get("servletNames");
            finalInfo.put("servletNames", servletNames.isEmpty() ? "" : servletNames.toString());
            result.add(finalInfo);
        }
        return result;
    }

    private static Map<String, Object> fillFilterInfo(Object filterServletNameMapping, Map<String, Object> filters, Map<String, Map<String, Object>> aggregatedData) throws NoSuchFieldException, IllegalAccessException {
        String filterName = (String) getFieldValue(filterServletNameMapping, "filterName");
        if (!aggregatedData.containsKey(filterName)) {
            Map<String, Object> info = new HashMap<>();
            info.put("filterName", filterName);
            Class<?> filterClass = (Class<?>) getFieldValue(filters.get(filterName), "filterClass");
            info.put("filterClass", filterClass.getName());
            info.put("urlPatterns", new LinkedHashSet<String>());
            info.put("servletNames", new LinkedHashSet<String>());
            aggregatedData.put(filterName, info);
        }
        return aggregatedData.get(filterName);
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
                    appendIfPresent(output, "", info.get("filterName"));
                    appendIfPresent(output, " -> ", info.get("filterClass"));
                    appendIfPresent(output, " -> URL:", info.get("urlPatterns"));
                    appendIfPresent(output, " -> Servlet:", info.get("servletNames"));
                    output.append("\n");
                }
            }
        }
        return output.toString();
    }

    private void appendIfPresent(StringBuilder sb, String prefix, String value) {
        if (value != null && !value.isEmpty()) {
            sb.append(prefix).append(value);
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

    @SuppressWarnings("Duplicates")
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                Class<?> clazz = thread.getContextClassLoader()
                        .loadClass("io.undertow.servlet.handlers.ServletRequestContext");
                Object requestContext = invokeMethod(clazz, "current", null, null);
                Object servletContext = invokeMethod(requestContext, "getCurrentServletContext", null, null);
                if (servletContext != null) {
                    contexts.add(servletContext);
                }
            } catch (Exception ignored) {
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
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
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
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

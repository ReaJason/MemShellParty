package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class ApusicFilterProbe {

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

    @SuppressWarnings({"unchecked", "Duplicates"})
    private List<Map<String, String>> collectFiltersData(Object context) throws Exception {
        // context -> com.apusic.web.container.WebContainer
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        // webModule -> com.apusic.deploy.runtime.WebModule
        Object webModule = getFieldValue(context, "webapp");
        Object[] filterMappings = (Object[]) invokeMethod(webModule, "getAllFilterMappings");
        for (Object fm : filterMappings) {
            // fm -> com.apusic.deploy.runtime.FilterMapping
            String name = (String) invokeMethod(fm, "getFilterName");
            if (!aggregatedData.containsKey(name)) {
                Map<String, Object> info = new HashMap<>();
                Object filterModel = invokeMethod(webModule, "getFilter", new Class[]{String.class}, new Object[]{name});
                info.put("filterName", name);
                info.put("filterClass", invokeMethod(filterModel, "getFilterClass"));
                info.put("urlPatterns", new LinkedHashSet<String>());
                info.put("servletNames", new LinkedHashSet<String>());
                aggregatedData.put(name, info);
            }
            Map<String, Object> info = aggregatedData.get(name);
            String urlPattern = (String) invokeMethod(fm, "getUrlPattern");
            if (urlPattern != null && !urlPattern.isEmpty()) ((Set<String>) info.get("urlPatterns")).add(urlPattern);
            String servletName = (String) invokeMethod(fm, "getServletName");
            if (servletName != null && !servletName.isEmpty()) ((Set<String>) info.get("servletNames")).add(servletName);
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

    @SuppressWarnings("all")
    private String formatFiltersData(Map<String, List<Map<String, String>>> allFiltersData) {
        StringBuilder output = new StringBuilder();
        for (Map.Entry<String, List<Map<String, String>>> entry : allFiltersData.entrySet()) {
            String context = entry.getKey();
            List<Map<String, String>> filters = entry.getValue();
            output.append("Context: ").append(context).append("\n");
            if (filters.isEmpty()) {
                output.append("No filters found\n");
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

    @SuppressWarnings("Duplicates")
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
     * context: com.apusic.web.container.WebContainer
     * context - webapp: com.apusic.deploy.runtime.WebModule
     * /usr/local/ass/lib/apusic.jar
     */
    @SuppressWarnings("Duplicates")
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("HouseKeeper")) {
                // Apusic 9.0 SPX
                Object sessionManager = getFieldValue(thread, "this$0");
                contexts.add(getFieldValue(sessionManager, "container"));
            } else if (thread.getName().contains("HTTPSession")) {
                // Apusic 9.0.1
                Object sessionManager = getFieldValue(thread, "this$0");
                Map<?, ?> contextMap = ((Map<?, ?>) getFieldValue(getFieldValue(sessionManager, "vhost"), "contexts"));
                contexts.addAll(contextMap.values());
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName + " for " + obj.getClass().getName());
    }

    public static Object invokeMethod(Object obj, String methodName) throws Exception {
        return invokeMethod(obj, methodName, null, null);
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

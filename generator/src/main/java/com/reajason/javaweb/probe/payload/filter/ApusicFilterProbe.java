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

    @SuppressWarnings("all")
    private List<Map<String, String>> collectFiltersData(Object context) {
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();

        try {
            Object webModule = getFieldValue(context, "webapp");
            if (webModule == null) {
                return Collections.emptyList();
            }

            Object[] filterMappings = (Object[]) invokeMethod(webModule, "getAllFilterMappings");
            if (filterMappings == null || filterMappings.length == 0) {
                return Collections.emptyList();
            }

            Object[] filters = (Object[]) invokeMethod(webModule, "getFilterList");
            Map<String, String> filterClassMap = new HashMap<>();
            if (filters != null) {
                for (Object filter : filters) {
                    String name = (String) invokeMethod(filter, "getName");
                    String className = (String) invokeMethod(filter, "getFilterClass");
                    if (name != null && className != null) {
                        filterClassMap.put(name, className);
                    }
                }
            }

            for (Object fm : filterMappings) {
                String name = (String) invokeMethod(fm, "getFilterName");
                if (name == null) {
                    continue;
                }
                if (!aggregatedData.containsKey(name)) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("filterName", name);
                    info.put("filterClass", filterClassMap.getOrDefault(name, "N/A"));
                    info.put("urlPatterns", new LinkedHashSet<String>());
                    aggregatedData.put(name, info);
                }
                Map<String, Object> info = aggregatedData.get(name);
                String urlPattern = (String) invokeMethod(fm, "getUrlPattern");
                if (urlPattern != null) {
                    ((Set<String>) info.get("urlPatterns")).add(urlPattern);
                }
            }
        } catch (Exception ignored) {
        }

        List<Map<String, String>> result = new ArrayList<>();
        for (Map<String, Object> entry : aggregatedData.values()) {
            Map<String, String> finalInfo = new HashMap<>();
            finalInfo.put("filterName", (String) entry.get("filterName"));
            finalInfo.put("filterClass", (String) entry.get("filterClass"));
            Set<?> urls = (Set<?>) entry.get("urlPatterns");
            finalInfo.put("urlPatterns", urls.isEmpty() ? "" : urls.toString());
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
     * context: com.apusic.web.container.WebContainer
     * context - webapp: com.apusic.deploy.runtime.WebModule
     * /usr/local/ass/lib/apusic.jar
     */
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

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    method = clazz.getDeclaredMethod(methodName);
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                throw new NoSuchMethodException("Method not found: " + methodName);
            }

            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
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

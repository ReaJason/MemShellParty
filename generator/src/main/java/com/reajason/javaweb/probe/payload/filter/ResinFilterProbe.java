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
        // context -> com.caucho.server.webapp.Application
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        // filterMapper -> com.caucho.server.dispatch.FilterMapper
        Object filterMapper = getFieldValue(context, "_filterMapper");
        // filterManager -> com.caucho.server.dispatch.FilterManager
        Object filterManager = getFieldValue(context, "_filterManager");
        if (filterMapper == null) return Collections.emptyList();
        ArrayList<Object> filterMappings = (ArrayList<Object>) getFieldValue(filterMapper, "_filterMap");
        for (Object filterMapping : filterMappings) {
            // filterMapping -> com.caucho.server.dispatch.FilterMapping
            String filterName = (String) invokeMethod(filterMapping, "getFilterName", null, null);
            if (!aggregatedData.containsKey(filterName)) {
                Map<String, Object> info = new HashMap<>();
                info.put("filterName", filterName);
                String filterClassName = (String) invokeMethod(filterMapping, "getFilterClassName", null, null);
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
                info.put("filterClass", filterClassName != null ? filterClassName : "N/A");
                info.put("urlPatterns", new LinkedHashSet<String>());
                info.put("servletNames", new LinkedHashSet<String>());
                aggregatedData.put(filterName, info);
            }
            Map<String, Object> info = aggregatedData.get(filterName);
            List<String> urlPatterns = new ArrayList<>();
            String urlPattern = (String) invokeMethod(filterMapping, "getURLPattern", null, null);
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
            if (!urlPatterns.isEmpty()) {
                ((Set<String>) info.get("urlPatterns")).addAll(urlPatterns);
            }
            List<String> servletNames = (List<String>) getFieldValue(filterMapping, "_servletNames");
            if (servletNames != null && !servletNames.isEmpty()) {
                ((Set<String>) info.get("servletNames")).addAll(servletNames);
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

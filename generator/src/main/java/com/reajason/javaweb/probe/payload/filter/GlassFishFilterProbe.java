package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class GlassFishFilterProbe {

    @Override
    public String toString() {
        StringBuilder msg = new StringBuilder();
        Map<String, List<Map<String, String>>> allFiltersData = new LinkedHashMap<String, List<Map<String, String>>>();
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg.append("context error: ").append(getErrorMessage(throwable));
        }
        if (contexts == null || contexts.isEmpty()) {
            msg.append("context not found\n");
        } else {
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
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();

        List filterMaps = (List) invokeMethod(context, "findFilterMaps");
        if (filterMaps == null || filterMaps.isEmpty()) return Collections.emptyList();

        Object[] filterDefs = (Object[]) invokeMethod(context, "findFilterDefs");

        for (Object fm : filterMaps) {
            String name = (String) invokeMethod(fm, "getFilterName");
            if (name == null) continue;
            if (!aggregatedData.containsKey(name)) {
                String filterClass = "N/A";
                if (filterDefs != null) {
                    Object filterDef = invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{name});
                    try {
                        filterClass = (String) invokeMethod(filterDef, "getFilterClass");
                    } catch (Throwable throwable) {
                        filterClass = (String) invokeMethod(filterDef, "getFilterClassName");
                    }
                    if (filterClass == null) {
                        Object filterConfig = invokeMethod(context, "findFilterConfig", new Class[]{String.class}, new Object[]{name});
                        Object filter = invokeMethod(filterConfig, "getFilter");
                        if (filter != null) filterClass = filter.getClass().getName();
                    }
                }
                Map<String, Object> info = new HashMap<>();
                info.put("filterName", name);
                info.put("filterClass", filterClass);
                info.put("urlPatterns", new LinkedHashSet<String>());
                info.put("servletNames", new LinkedHashSet<String>());
                aggregatedData.put(name, info);
            }
            Map<String, Object> info = aggregatedData.get(name);
            String[] urls = null;
            try {
                urls = (String[]) invokeMethod(fm, "getURLPatterns");
            } catch (Exception e) {
                // Tomcat 5
                String urlPattern = (String) invokeMethod(fm, "getURLPattern");
                if (urlPattern != null) {
                    urls = new String[]{urlPattern};
                }
            }
            if (urls != null) ((Set<String>) info.get("urlPatterns")).addAll(Arrays.asList(urls));
            String[] servletNames = null;
            try {
                servletNames = (String[]) invokeMethod(fm, "getServletNames");
            } catch (Exception e) {
                // Tomcat 5
                String servletName = (String) invokeMethod(fm, "getServletName");
                if (servletName != null) {
                    servletNames = new String[]{servletName};
                }
            }
            if (servletNames != null) ((Set<String>) info.get("servletNames")).addAll(Arrays.asList(servletNames));
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
                    appendIfPresent(output, "", info.get("filterName"), "");
                    appendIfPresent(output, " -> ", info.get("filterClass"), "");
                    appendIfPresent(output, " -> URL:", info.get("urlPatterns"), "");
                    appendIfPresent(output, " -> Servlet:", info.get("servletNames"), "");
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
    private static String repeatString(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(invokeMethod(context, "getServletContext"), "getContextPath");
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
     * com.sun.enterprise.web.WebModule
     * /xxx/modules/web-glue.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                for (Object value : childrenMap.values()) {
                    Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                    contexts.addAll(children.values());
                }
            }
        }
        return contexts;
    }

    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
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

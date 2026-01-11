package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class WebSphereFilterProbe {

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
        // context -> com.ibm.ws.webcontainer.webapp.WebAppImpl
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        // filterManager -> com.ibm.ws.webcontainer.filter.WebAppFilterManager
        Object filterManager = getFieldValue(context, "filterManager");
        // webAppConfig -> com.ibm.ws.webcontainer.webapp.WebAppConfigurationImpl
        Object webAppConfig = getFieldValue(context, "config");
        try {
            // WebLogic 12+
            List<Object> uriFilterMappingInfos = (List<Object>) getFieldValue(webAppConfig, "uriFilterMappingInfos");
            for (Object uriFilterMappingInfo : uriFilterMappingInfos) {
                // uriFilterMappingInfo -> com.ibm.ws.webcontainer.filter.FilterMapping
                Map<String, Object> info = filterFilterInfo1(uriFilterMappingInfo, aggregatedData);
                String urlPattern = (String) invokeMethod(uriFilterMappingInfo, "getUrlPattern", null, null);
                if (urlPattern != null && !urlPattern.isEmpty()) {
                    ((Set<String>) info.get("urlPatterns")).add(urlPattern);
                }
            }
            List<Object> servletFilterMappingInfos = (List<Object>) getFieldValue(webAppConfig, "servletFilterMappingInfos");
            for (Object servletFilterMappingInfo : servletFilterMappingInfos) {
                // servletFilterMappingInfo -> com.ibm.ws.webcontainer.filter.FilterMapping
                Map<String, Object> info = filterFilterInfo1(servletFilterMappingInfo, aggregatedData);
                String servletName = (String) invokeMethod(invokeMethod(servletFilterMappingInfo, "getServletConfig"), "getServletName");
                if (servletName != null && !servletName.isEmpty()) {
                    ((Set<String>) info.get("servletNames")).add(servletName);
                }
            }
        } catch (Throwable throwable) {
            // WebLogic 10.3.6
            List<Object> uriFilterMappings = (List<Object>) getFieldValue(filterManager, "_uriFilterMappings");
            for (Object uriFilterMapping : uriFilterMappings) {
                // uriFilterMapping -> com.ibm.ws.webcontainer.filter.WebAppFilterManager$FilterMappingInfo
                Map<String, Object> info = fillFilterInfo2(uriFilterMapping, aggregatedData, webAppConfig);
                String urlPattern = (String) getFieldValue(uriFilterMapping, "_filterURI");
                if (urlPattern != null && !urlPattern.isEmpty()) {
                    ((Set<String>) info.get("urlPatterns")).add(urlPattern);
                }
            }
            List<Object> servletFilterMappings = (List<Object>) getFieldValue(filterManager, "_servletFilterMappings");
            for (Object servletFilterMapping : servletFilterMappings) {
                // servletFilterMapping -> com.ibm.ws.webcontainer.filter.WebAppFilterManager$FilterMappingInfo
                Map<String, Object> info = fillFilterInfo2(servletFilterMapping, aggregatedData, webAppConfig);
                String servletName = (String) getFieldValue(servletFilterMapping, "_filterServlet");
                if (servletName != null && !servletName.isEmpty()) {
                    ((Set<String>) info.get("servletNames")).add(servletName);
                }
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

    private static Map<String, Object> filterFilterInfo1(Object uriFilterMappingInfo, Map<String, Map<String, Object>> aggregatedData) throws Exception {
        Object filterConfig = getFieldValue(uriFilterMappingInfo, "filterConfig");
        String filterName = (String) invokeMethod(filterConfig, "getFilterName", null, null);
        if (!aggregatedData.containsKey(filterName)) {
            String filterClassName = (String) invokeMethod(filterConfig, "getFilterClassName", null, null);
            Map<String, Object> info = new HashMap<>();
            info.put("filterName", filterName);
            info.put("filterClass", filterClassName);
            info.put("urlPatterns", new LinkedHashSet<>());
            info.put("servletNames", new LinkedHashSet<>());
            aggregatedData.put(filterName, info);
        }
        return aggregatedData.get(filterName);
    }

    private static Map<String, Object> fillFilterInfo2(Object servletFilterMapping, Map<String, Map<String, Object>> aggregatedData, Object webAppConfig) throws Exception {
        String filterName = (String) getFieldValue(servletFilterMapping, "_filterName");
        if (!aggregatedData.containsKey(filterName)) {
            Object filterConfig = invokeMethod(webAppConfig, "getFilterInfo", new Class[]{String.class}, new Object[]{filterName});
            String filterClassName = (String) invokeMethod(filterConfig, "getFilterClassName", null, null);
            Map<String, Object> info = new HashMap<>();
            info.put("filterName", filterName);
            info.put("filterClass", filterClassName);
            info.put("urlPatterns", new LinkedHashSet<>());
            info.put("servletNames", new LinkedHashSet<>());
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


    /**
     * com.ibm.ws.webcontainer.webapp.WebAppImpl
     * /opt/IBM/WebSphere/AppServer/plugins/com.ibm.ws.webcontainer.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Object[] threadLocals = null;
        boolean raw = false;
        try {
            // WebSphere Liberty
            threadLocals = (Object[]) getFieldValue(Thread.currentThread(), "wsThreadLocals");
        } catch (NoSuchFieldException ignored) {
        }
        if (threadLocals == null) {
            // Open Liberty
            threadLocals = (Object[]) getFieldValue(getFieldValue(Thread.currentThread(), "threadLocals"), "table");
            raw = true;
        }
        for (Object threadLocal : threadLocals) {
            if (threadLocal == null) {
                continue;
            }
            Object value = threadLocal;
            if (raw) {
                value = getFieldValue(threadLocal, "value");
            }
            if (value == null) {
                continue;
            }
            // for websphere 7.x
            if (value.getClass().getName().endsWith("FastStack")) {
                Object[] stackList = (Object[]) getFieldValue(value, "stack");
                for (Object stack : stackList) {
                    try {
                        Object config = getFieldValue(stack, "config");
                        contexts.add(getFieldValue(getFieldValue(config, "context"), "context"));
                    } catch (Exception ignored) {
                    }
                }
            } else if (value.getClass().getName().endsWith("WebContainerRequestState")) {
                Object webApp = invokeMethod(getFieldValue(getFieldValue(value, "currentThreadsIExtendedRequest"), "_dispatchContext"), "getWebApp", null, null);
                contexts.add(getFieldValue(getFieldValue(webApp, "facade"), "context"));
            }
        }
        return contexts;
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

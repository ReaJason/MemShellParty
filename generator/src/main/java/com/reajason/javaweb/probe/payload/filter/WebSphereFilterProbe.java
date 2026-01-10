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
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        try {
            Object filterManager = getFieldValue(context, "filterManager");
            Object webAppConfig = getFieldValue(context, "config");
            try {
                List uriFilterMappingInfos = (List) getFieldValue(webAppConfig, "uriFilterMappingInfos");
                if (uriFilterMappingInfos == null || uriFilterMappingInfos.isEmpty()) {
                    return Collections.emptyList();
                }
                for (Object uriFilterMappingInfo : uriFilterMappingInfos) {
                    Object filterConfig = getFieldValue(uriFilterMappingInfo, "filterConfig");
                    String filterName = (String) invokeMethod(filterConfig, "getFilterName", null, null);
                    Collection urlPatternMappings = (Collection) invokeMethod(filterConfig, "getUrlPatternMappings", null, null);
                    String urlPattern = (String) invokeMethod(uriFilterMappingInfo, "getUrlPattern", null, null);
                    if (!aggregatedData.containsKey(filterName)) {
                        String filterClassName = (String) invokeMethod(filterConfig, "getFilterClassName", null, null);
                        Map<String, Object> info = new HashMap<>();
                        info.put("filterName", filterName);
                        info.put("filterClass", filterClassName);
                        LinkedHashSet<String> urlPatterns = new LinkedHashSet<>();
                        if (urlPattern != null && !urlPattern.isEmpty()) {
                            urlPatterns.add(urlPattern);
                        }
                        if (urlPatternMappings != null) {
                            urlPatterns.addAll(urlPatternMappings);
                        }
                        info.put("urlPatterns", urlPatterns);
                        aggregatedData.put(filterName, info);
                    } else {
                        Set urlPatterns = (Set) aggregatedData.get(filterName).get("urlPatterns");
                        if (urlPattern != null && !urlPattern.isEmpty()) {
                            urlPatterns.add(urlPattern);
                        }
                        if (urlPatternMappings != null) {
                            urlPatterns.addAll(urlPatternMappings);
                        }
                    }
                }
            } catch (Throwable throwable) {
                throwable.printStackTrace();
                // WebLogic 10.3.6
                List uriFilterMappings = (List) getFieldValue(filterManager, "_uriFilterMappings");
                for (Object uriFilterMapping : uriFilterMappings) {
                    String filterName = (String) getFieldValue(uriFilterMapping, "_filterName");
                    String urlPattern = (String) getFieldValue(uriFilterMapping, "_filterURI");
                    if (!aggregatedData.containsKey(filterName)) {
                        Object filterConfig = invokeMethod(webAppConfig, "getFilterInfo", new Class[]{String.class}, new Object[]{filterName});
                        String filterClassName = (String) invokeMethod(filterConfig, "getFilterClassName", null, null);
                        Map<String, Object> info = new HashMap<>();
                        info.put("filterName", filterName);
                        info.put("filterClass", filterClassName);
                        LinkedHashSet<String> urlPatterns = new LinkedHashSet<>();
                        if (urlPattern != null && !urlPattern.isEmpty()) {
                            urlPatterns.add(urlPattern);
                        }
                        info.put("urlPatterns", urlPatterns);
                        aggregatedData.put(filterName, info);
                    } else {
                        if (urlPattern != null && !urlPattern.isEmpty()) {
                            ((Set) aggregatedData.get(filterName).get("urlPatterns")).add(urlPattern);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        List<Map<String, String>> result = new ArrayList<>();
        for (Map<String, Object> entry : aggregatedData.values()) {
            Map<String, String> finalInfo = new HashMap<>();
            finalInfo.put("filterName", (String) entry.get("filterName"));
            finalInfo.put("filterClass", (String) entry.get("filterClass"));
            Set<?> urls = (Set<?>) entry.get("urlPatterns");
            finalInfo.put("urlPatterns", urls.isEmpty() ? "[/*]" : Arrays.toString(urls.toArray()));
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

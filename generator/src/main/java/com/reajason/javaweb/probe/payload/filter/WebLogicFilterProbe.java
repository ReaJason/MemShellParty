package com.reajason.javaweb.probe.payload.filter;

import javax.management.MBeanServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class WebLogicFilterProbe {

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
        // context -> weblogic.servlet.internal.WebAppServletContext
        // filterManager -> weblogic.servlet.internal.FilterManager
        Object filterManager = getFieldValue(context, "filterManager");
        Map<String, Object> filters = (Map<String, Object>) getFieldValue(filterManager, "filters");
        List<Object> filterPatternList = (ArrayList<Object>) getFieldValue(filterManager, "filterPatternList");
        List<Object> filterServletList = (ArrayList<Object>) getFieldValue(filterManager, "filterServletList");
        Map<String, Map<String, Object>> aggregatedData = new LinkedHashMap<>();
        for (Object filterInfo : filterPatternList) {
            // filterInfo -> weblogic.servlet.internal.FilterManager$FilterInfo
            Object urlMap = getFieldValue(filterInfo, "map");
            String filterName = (String) getFieldValue(filterInfo, "filterName");
            if (filterName == null) {
                // WebLogic 10.3.6
                Object[] mapValues = (Object[]) invokeMethod(urlMap, "values", null, null);
                filterName = ((String) mapValues[0]);
            }
            Map<String, Object> info = fillFilterInfo(aggregatedData, filterName, filters);
            String[] urlPatterns = (String[]) invokeMethod(urlMap, "keys", null, null);
            if (urlPatterns != null) {
                ((Set<String>) info.get("urlPatterns")).addAll(Arrays.asList(urlPatterns));
            }
        }
        for (Object filterInfo : filterServletList) {
            // filterInfo -> weblogic.servlet.internal.FilterManager$FilterInfo
            String filterName = (String) getFieldValue(filterInfo, "filterName");
            Map<String, Object> info = fillFilterInfo(aggregatedData, filterName, filters);
            String servletName = (String) getFieldValue(filterInfo, "servletName");
            if (servletName != null) {
                ((Set<String>) info.get("servletNames")).add(servletName);
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

    private static Map<String, Object> fillFilterInfo(Map<String, Map<String, Object>> aggregatedData, String filterName, Map<String, Object> filters) throws Exception {
        if (!aggregatedData.containsKey(filterName)) {
            // filterWrapper -> weblogic.servlet.internal.FilterWrapper
            Object filterWrapper = filters.get(filterName);
            String filterClassName = null;
            try {
                filterClassName = (String) getFieldValue(filterWrapper, "filterClassName");
            } catch (NoSuchFieldException e) {
                // WebLogic 10.3.6
                filterClassName = (String) getFieldValue(filterWrapper, "filterclass");
            }
            if (filterClassName == null) {
                Object filter = getFieldValue(filterWrapper, "filter");
                if (filter != null) {
                    filterClassName = filter.getClass().getName();
                }
            }
            Map<String, Object> info = new HashMap<>();
            info.put("filterName", filterName);
            info.put("filterClass", filterClassName);
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


    /**
     * weblogic.servlet.internal.WebAppServletContext
     * /opt/oracle/wls1036/server/lib/weblogic.jar
     * /u01/oracle/wlserver/modules/com.oracle.weblogic.servlet.jar
     */
    public static Set<Object> getContext() throws Exception {
        Set<Object> webappContexts = new HashSet<Object>();
        MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        Map<String, Object> objectsByObjectName = (Map<String, Object>) getFieldValue(platformMBeanServer, "objectsByObjectName");
        for (Map.Entry<String, Object> entry : objectsByObjectName.entrySet()) {
            String key = entry.getKey();
            if (key.contains("Type=WebAppComponentRuntime")) {
                Object value = entry.getValue();
                Object managedResource = getFieldValue(value, "managedResource");
                if (managedResource != null && managedResource.getClass().getSimpleName().equals("WebAppRuntimeMBeanImpl")) {
                    webappContexts.add(getFieldValue(managedResource, "context"));
                }
            }
        }
        try {
            Object workEntry = getFieldValue(Thread.currentThread(), "workEntry");
            Object request = null;
            try {
                Object connectionHandler = getFieldValue(workEntry, "connectionHandler");
                request = getFieldValue(connectionHandler, "request");
            } catch (Exception x) {
                // WebLogic 10.3.6
                request = workEntry;
            }
            if (request != null) {
                webappContexts.add(getFieldValue(request, "context"));
            }
        } catch (Throwable ignored) {
        }
        return webappContexts;
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

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
            Object filterManager = getFieldValue(context, "filterManager");
            Map<String, Object> filters = (Map<String, Object>) getFieldValue(filterManager, "filters");
            List<Object> filterPatternList = (ArrayList<Object>) getFieldValue(filterManager, "filterPatternList");
            if (filterPatternList == null || filterPatternList.isEmpty()) {
                return Collections.emptyList();
            }
            for (Object filterInfo : filterPatternList) {
                Map<String, String> info = new HashMap<>();
                Object urlMap = getFieldValue(filterInfo, "map");
                String filterName = (String) getFieldValue(filterInfo, "filterName");
                if (filterName == null) {
                    // WebLogic 10.3.6
                    Object[] mapValues = (Object[]) invokeMethod(urlMap, "values", null, null);
                    filterName = ((String) mapValues[0]);
                }
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
                info.put("filterName", filterName);
                info.put("filterClass", filterClassName);
                String[] urlPatterns = (String[]) invokeMethod(urlMap, "keys", null, null);
                info.put("urlPatterns", Arrays.toString(urlPatterns));
                result.add(info);
            }
        } catch (Exception e) {
            e.printStackTrace();
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

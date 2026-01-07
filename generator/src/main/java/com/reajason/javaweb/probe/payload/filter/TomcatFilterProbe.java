package com.reajason.javaweb.probe.payload.filter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author ReaJason
 */
public class TomcatFilterProbe {

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
        List<Map<String, String>> filtersList = new ArrayList<Map<String, String>>();
        Object[] filterMaps = (Object[]) invokeMethod(context, "findFilterMaps", null, null);
        if (filterMaps == null || filterMaps.length == 0) {
            return filtersList;
        }
        Object[] filterDefs = (Object[]) invokeMethod(context, "findFilterDefs", null, null);
        Map<String, Object> filterConfigs = null;
        try {
            filterConfigs = (Map<String, Object>) getFieldValue(context, "filterConfigs");
        } catch (Exception ignored) {
        }
        Map<String, Object> filterDefMap = new HashMap<String, Object>();
        if (filterDefs != null) {
            for (Object filterDef : filterDefs) {
                String filterName = (String) invokeMethod(filterDef, "getFilterName", null, null);
                if (filterName != null) {
                    filterDefMap.put(filterName, filterDef);
                }
            }
        }
        Set<String> processedFilters = new HashSet<String>();
        for (Object filterMap : filterMaps) {
            String filterName = (String) invokeMethod(filterMap, "getFilterName", null, null);
            if (filterName == null || processedFilters.contains(filterName)) {
                continue;
            }
            processedFilters.add(filterName);

            Map<String, String> filterInfo = new LinkedHashMap<String, String>();
            filterInfo.put("filterName", filterName);
            String filterClass = null;
            Object filterDef = filterDefMap.get(filterName);
            if (filterDef != null) {
                try {
                    filterClass = (String) invokeMethod(filterDef, "getFilterClass", null, null);
                } catch (Exception e) {
                    try {
                        Object clazz = invokeMethod(filterDef, "getFilterClass", null, null);
                        if (clazz instanceof Class) {
                            filterClass = ((Class<?>) clazz).getName();
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            if (filterClass == null || filterClass.isEmpty() || filterClass.equals("N/A")) {
                try {
                    if (filterConfigs != null) {
                        Object filterConfig = filterConfigs.get(filterName);
                        if (filterConfig != null) {
                            Object filter = invokeMethod(filterConfig, "getFilter", null, null);
                            if (filter != null) {
                                filterClass = filter.getClass().getName();
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }

            filterInfo.put("filterClass", filterClass != null ? filterClass : "N/A");

            List<String> urlPatternsList = new ArrayList<String>();
            List<String> servletNamesList = new ArrayList<String>();

            for (Object fm : filterMaps) {
                String mappingFilterName = (String) invokeMethod(fm, "getFilterName", null, null);
                if (filterName.equals(mappingFilterName)) {
                    String[] urlPatterns = null;
                    try {
                        urlPatterns = (String[]) invokeMethod(fm, "getURLPatterns", null, null);
                    } catch (Exception e) {
                        try {
                            Object urlPattern = getFieldValue(fm, "urlPattern");
                            if (urlPattern instanceof String) {
                                urlPatterns = new String[] { (String) urlPattern };
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    if (urlPatterns != null && urlPatterns.length > 0) {
                        for (String pattern : urlPatterns) {
                            urlPatternsList.add(pattern);
                        }
                    }

                    String[] servletNames = null;
                    try {
                        servletNames = (String[]) invokeMethod(fm, "getServletNames", null, null);
                    } catch (Exception e) {
                        try {
                            Object servletName = getFieldValue(fm, "servletName");
                            if (servletName instanceof String) {
                                servletNames = new String[] { (String) servletName };
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    if (servletNames != null && servletNames.length > 0) {
                        for (String servletName : servletNames) {
                            servletNamesList.add(servletName);
                        }
                    }
                }
            }

            if (!urlPatternsList.isEmpty()) {
                StringBuilder patterns = new StringBuilder();
                for (int j = 0; j < urlPatternsList.size(); j++) {
                    patterns.append(urlPatternsList.get(j));
                    if (j < urlPatternsList.size() - 1) {
                        patterns.append(", ");
                    }
                }
                filterInfo.put("urlPatterns", patterns.toString());
            }

            if (!servletNamesList.isEmpty()) {
                StringBuilder servletNames = new StringBuilder();
                for (int j = 0; j < servletNamesList.size(); j++) {
                    servletNames.append(servletNamesList.get(j));
                    if (j < servletNamesList.size() - 1) {
                        servletNames.append(", ");
                    }
                }
                filterInfo.put("servletNames", servletNames.toString());
            }

            filtersList.add(filterInfo);
        }

        return filtersList;
    }

    @SuppressWarnings("all")
    private String formatFiltersData(Map<String, List<Map<String, String>>> allFiltersData) {
        StringBuilder output = new StringBuilder();
        for (Map.Entry<String, List<Map<String, String>>> entry : allFiltersData.entrySet()) {
            String contextRoot = entry.getKey();
            List<Map<String, String>> filters = entry.getValue();

            output.append("Context: ").append(contextRoot).append("\n");

            if (filters.isEmpty()) {
                output.append("No filters found\n");
                continue;
            }

            if (filters.size() == 1 && filters.get(0).containsKey("error")) {
                output.append(filters.get(0).get("error")).append("\n");
                continue;
            }

            for (Map<String, String> filterInfo : filters) {
                String filterName = filterInfo.get("filterName");
                String filterClass = filterInfo.get("filterClass");
                String urlPatterns = filterInfo.get("urlPatterns");
                String servletNames = filterInfo.get("servletNames");

                if (filterName != null) {
                    output.append(filterName);
                }
                if (filterClass != null) {
                    output.append(" -> ").append(filterClass);
                }

                if (urlPatterns != null && !urlPatterns.isEmpty()) {
                    output.append(" -> URL:[").append(urlPatterns).append("]");
                }

                if (servletNames != null && !servletNames.isEmpty()) {
                    output.append(" -> Servlet:[").append(servletNames).append("]");
                }

                output.append("\n");
            }
        }

        return output.toString();
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
            r = (String) invokeMethod(invokeMethod(context, "getServletContext", null, null), "getContextPath", null,
                    null);
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
     * org.apache.catalina.core.StandardContext
     * /usr/local/tomcat/server/lib/catalina.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            String threadName = thread.getName();
            if (threadName.contains("ContainerBackgroundProcessor")) {
                Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                for (Object value : childrenMap.values()) {
                    Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                    contexts.addAll(children.values());
                }
            } else if (threadName.contains("Poller") && !threadName.contains("ajp")) {
                try {
                    Object proto = getFieldValue(getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "handler"), "proto");
                    Object engine = getFieldValue(getFieldValue(getFieldValue(getFieldValue(proto, "adapter"), "connector"), "service"), "engine");
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(engine, "children");
                    for (Object value : childrenMap.values()) {
                        Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                        contexts.addAll(children.values());
                    }
                } catch (Exception ignored) {
                }
            } else if (thread.getContextClassLoader() != null) {
                String name = thread.getContextClassLoader().getClass().getSimpleName();
                if (name.matches(".+WebappClassLoader")) {
                    Object resources = getFieldValue(thread.getContextClassLoader(), "resources");
                    // need WebResourceRoot not DirContext
                    if (resources != null && resources.getClass().getName().endsWith("Root")) {
                        Object context = getFieldValue(resources, "context");
                        contexts.add(context);
                    }
                }
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

package com.reajason.javaweb.probe.payload;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author ReaJason
 * @since 2025/7/29
 */
public class BasicInfoPrinter {
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sb.append("# Generated At ").append(sdf.format(new Date())).append("\n");
        sb.append("SystemProps:\n");
        Properties properties = System.getProperties();
        for (Object key : properties.keySet()) {
            sb.append(key).append(": ").append(properties.get(key)).append("\n");
        }
        sb.append("\n===========================================\n");
        sb.append("\nThreadStacks:\n");
        Map<Thread, StackTraceElement[]> allStackTraces = Thread.getAllStackTraces();
        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        Set<String> classNames = new HashSet<>();
        for (Map.Entry<Thread, StackTraceElement[]> threadEntry : allStackTraces.entrySet()) {
            Thread thread = threadEntry.getKey();
            StackTraceElement[] stackTrace = threadEntry.getValue();
            ThreadInfo threadInfo = threadMXBean.getThreadInfo(thread.getId());
            sb.append("\"").append(thread.getName()).append("\" #").append(thread.getId());
            if (thread.isDaemon()) {
                sb.append(" daemon");
            }
            sb.append(" [").append(thread.getState()).append("]");
            if (threadInfo != null && threadInfo.getLockName() != null) {
                sb.append(" on ").append(threadInfo.getLockName());
            }
            sb.append("\n");
            sb.append("   java.lang.Thread.State: ").append(thread.getState()).append("\n");
            for (StackTraceElement element : stackTrace) {
                sb.append("\tat ").append(element.toString()).append("\n");
                String className = element.getClassName();

                if (!className.startsWith("java.")
                        && !className.startsWith("jdk.")
                        && !className.startsWith("sun.")
                        && !className.startsWith("com.sun.")
                        && !className.startsWith("javax.")
                ) {
                    classNames.add(className);
                }
            }
            sb.append("\n");
        }
        sb.append("\n===========================================\n");
        sb.append("\nStackClassNames:\n");
        List<String> strings = new ArrayList<>(classNames);
        Collections.sort(strings);
        for (String className : strings) {
            sb.append(className).append("\n");
        }
        return sb.toString();
    }
}

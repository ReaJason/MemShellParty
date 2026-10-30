package com.reajason.javaweb.memshell;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

/**
 * 三类 SPI 共用的逐条容错发现。服务描述符无法继续迭代时停止，单个实现失败时继续下一条。
 */
final class SpiLoader {
    private SpiLoader() {
    }

    static <T> List<T> load(Class<T> service, List<String> loadErrors) {
        List<T> providers = new ArrayList<>();
        Iterator<T> iterator = ServiceLoader.load(service).iterator();
        while (true) {
            boolean hasNext;
            try {
                hasNext = iterator.hasNext();
            } catch (ServiceConfigurationError | LinkageError | RuntimeException e) {
                loadErrors.add("读取 " + service.getSimpleName() + " SPI 失败: " + message(e));
                break;
            }
            if (!hasNext) {
                break;
            }
            try {
                providers.add(iterator.next());
            } catch (ServiceConfigurationError | LinkageError | RuntimeException e) {
                loadErrors.add("加载 " + service.getSimpleName() + " SPI 条目失败: " + message(e));
            }
        }
        return providers;
    }

    static String message(Throwable throwable) {
        StringBuilder message = new StringBuilder(messageOf(throwable));
        Throwable cause = throwable.getCause();
        int depth = 0;
        while (cause != null && cause != throwable && depth++ < 8) {
            message.append(": ").append(messageOf(cause));
            throwable = cause;
            cause = cause.getCause();
        }
        return message.toString();
    }

    private static String messageOf(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isEmpty() ? throwable.getClass().getName() : message;
    }
}

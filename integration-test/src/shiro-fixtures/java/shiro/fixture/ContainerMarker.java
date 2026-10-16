package shiro.fixture;

import java.io.FileOutputStream;

/**
 * CVE-2016-4437 验收（F22-B）用的构造器标记类：装载器 defineClass + newInstance 触发构造器，
 * 在目标容器里写一个标记文件，随后用命令通道 cat 读回即证明"自定义 class 在目标上执行了"。
 *
 * <p>必须由 compileShiroExploitFixtures 任务以 Java 8 字节码编译（目标是 JDK 8u102），
 * 不进 test 源码集——本类只以字节形式被测试读取，不在测试 JVM 里实例化。
 */
public class ContainerMarker {

    /**
     * 容器内标记文件路径（容器独属于 CVE20164437ContainerTest，路径无需按模块隔离）；
     * 测试侧按资源读字节、编译期够不到本类，路径字面量在两侧各写一份，改动须同步。
     */
    public static final String MARKER_PATH = "/tmp/cve-2016-4437-marker";

    public ContainerMarker() throws Exception {
        FileOutputStream out = new FileOutputStream(MARKER_PATH);
        try {
            out.write("ran".getBytes("UTF-8"));
        } finally {
            out.close();
        }
    }
}

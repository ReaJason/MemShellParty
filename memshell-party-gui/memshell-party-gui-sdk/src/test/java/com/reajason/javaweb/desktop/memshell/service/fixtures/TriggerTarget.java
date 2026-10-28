package com.reajason.javaweb.desktop.memshell.service.fixtures;

/** Swing 端到端测试使用的本地触发夹具。 */
public class TriggerTarget {

    public static final String PROPERTY = "memshellparty.bytecode.test.trigger";
    public static final String CLINIT_PROPERTY = PROPERTY + ".clinit";

    public static String initialized = initialize();

    public TriggerTarget() {
        System.setProperty(PROPERTY, "noarg");
    }

    public TriggerTarget(String value) {
        System.setProperty(PROPERTY, "string:" + value);
    }

    @Override
    public String toString() {
        System.setProperty(PROPERTY, "toString");
        return "TriggerTarget";
    }

    private static String initialize() {
        System.setProperty(CLINIT_PROPERTY, "yes");
        return "initialized";
    }
}

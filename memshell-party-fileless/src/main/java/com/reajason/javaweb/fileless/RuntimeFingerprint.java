package com.reajason.javaweb.fileless;

import java.util.Locale;

public final class RuntimeFingerprint {
    private final String vendor;
    private final String runtimeVersion;
    private final String vmName;
    private final String vmVersion;
    private final String osName;
    private final String osArch;
    private final String dataModel;

    public RuntimeFingerprint(String vendor, String runtimeVersion, String vmName, String vmVersion,
                              String osName, String osArch, String dataModel) {
        this.vendor = value(vendor);
        this.runtimeVersion = value(runtimeVersion);
        this.vmName = value(vmName);
        this.vmVersion = value(vmVersion);
        this.osName = value(osName);
        this.osArch = value(osArch);
        this.dataModel = value(dataModel);
    }

    public static RuntimeFingerprint detect() {
        return new RuntimeFingerprint(property("java.vendor"), property("java.runtime.version"),
                property("java.vm.name"), property("java.vm.version"), property("os.name"),
                property("os.arch"), property("sun.arch.data.model"));
    }

    private static String property(String name) {
        try {
            return value(System.getProperty(name));
        } catch (SecurityException ignored) {
            return "";
        }
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    public String getOsName() {
        return osName;
    }

    boolean isLinuxX86_64() {
        return osName.toLowerCase(Locale.ENGLISH).contains("linux")
                && "amd64".equals(osArch) && "64".equals(dataModel);
    }

    boolean isLinuxAarch64() {
        return osName.toLowerCase(Locale.ENGLISH).contains("linux")
                && ("aarch64".equals(osArch) || "arm64".equals(osArch)) && "64".equals(dataModel);
    }

    boolean isOpenJ9() {
        String normalized = vmName.toLowerCase(Locale.ENGLISH);
        return normalized.contains("openj9") || normalized.contains("j9");
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RuntimeFingerprint)) {
            return false;
        }
        RuntimeFingerprint other = (RuntimeFingerprint) obj;
        return vendor.equals(other.vendor)
                && runtimeVersion.equals(other.runtimeVersion)
                && vmName.equals(other.vmName)
                && vmVersion.equals(other.vmVersion)
                && osName.equals(other.osName)
                && osArch.equals(other.osArch)
                && dataModel.equals(other.dataModel);
    }

    @Override
    public int hashCode() {
        int result = vendor.hashCode();
        result = 31 * result + runtimeVersion.hashCode();
        result = 31 * result + vmName.hashCode();
        result = 31 * result + vmVersion.hashCode();
        result = 31 * result + osName.hashCode();
        result = 31 * result + osArch.hashCode();
        result = 31 * result + dataModel.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "vendor=" + vendor + ", runtime=" + runtimeVersion + ", vm=" + vmName
                + "/" + vmVersion + ", os=" + osName + "/" + osArch
                + ", dataModel=" + dataModel;
    }
}

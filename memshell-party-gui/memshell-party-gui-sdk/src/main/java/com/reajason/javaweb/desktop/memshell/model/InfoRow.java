package com.reajason.javaweb.desktop.memshell.model;

/**
 * 生成结果基本信息的一行：{@code name} 为行名，{@code value} 为完整值。
 * <p>
 * {@code copyValue} 供「值里只有一部分需要复制」的行使用（如「内存马类名」展示
 * {@code 类名 (大小)} 但复制只取类名）；缺省与 {@code value} 相同。
 * 界面按需截断展示（{@code displayFull} 的行除外），复制与文本输出一律用完整值。
 */
public class InfoRow {
    private final String name;
    private final String value;
    private final String copyValue;
    private final boolean displayFull;

    public InfoRow(String name, String value) {
        this(name, value, value);
    }

    public InfoRow(String name, String value, String copyValue) {
        this(name, value, copyValue, false);
    }

    public InfoRow(String name, String value, String copyValue, boolean displayFull) {
        this.name = name;
        this.value = value == null ? "" : value;
        this.copyValue = copyValue == null ? this.value : copyValue;
        this.displayFull = displayFull;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getCopyValue() {
        return copyValue;
    }

    /**
     * 界面是否完整展示 {@code value}（不截断）。类名这类必须认全的标识行置为 {@code true}；
     * 缺省仍按长度截断，避免 Custom 的 Base64 之类超长值撑爆布局。
     */
    public boolean isDisplayFull() {
        return displayFull;
    }
}

package com.reajason.javaweb.desktop.memshell.extension;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;

/**
 * 结果区的一个动作按钮，由 {@link GuiExtension#resultActions()} 提供。
 */
public interface ResultAction {

    /**
     * 按钮文案。
     */
    String label();

    /**
     * 是否靠右对齐，默认 {@code false}（从左往右排）。
     *
     * <p>同一行里靠左的动作排在前面，靠右的贴到最右边 —— 宿主自己的收尾动作
     * （如"加入我的 Shell 列表"）用 {@code true}，和内置动作在视觉上分开。
     */
    default boolean alignRight() {
        return false;
    }

    /**
     * 这份结果是否适用这个动作，默认都适用。
     *
     * <p>返回 {@code false} 时按钮在有结果的情况下也保持置灰 —— 宿主只对自己家的工具提供动作时用
     * （如"加入我的 Shell 列表"之于内置工具：它们的密码/密钥字段名不一样，套上去只会填错）。
     */
    default boolean supports(DesktopMemShellGenerateResult result) {
        return true;
    }

    /**
     * 点击时执行（已生成结果、且 {@link #supports} 通过才会被调用）。
     */
    void perform(DesktopMemShellGenerateResult result);
}

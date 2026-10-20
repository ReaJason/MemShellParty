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
     * 点击后的忙碌态文案，默认 {@code null}：按钮不进入加载态，动作瞬时完成。
     *
     * <p>返回非空时，点击后按钮立即置灰并换成该文案，直到
     * {@link #perform(DesktopMemShellGenerateResult, Runnable)} 调用 {@code done} 才恢复。
     * 需要等待目标响应的动作（如注入内存马）用它避免重复点击，也让用户看到「正在执行」。
     */
    default String busyLabel() {
        return null;
    }

    /**
     * 点击时执行，并在动作结束时报告完成。默认实现转调
     * {@link #perform(DesktopMemShellGenerateResult)} 后立即报告完成。
     *
     * <p>异步动作覆盖本方法，在真正结束时调用 {@code done}（可在任意线程调用，
     * 结果区会切回 EDT 恢复按钮）；同步动作保持覆盖 {@code perform} 即可。
     */
    default void perform(DesktopMemShellGenerateResult result, Runnable done) {
        perform(result);
        done.run();
    }

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

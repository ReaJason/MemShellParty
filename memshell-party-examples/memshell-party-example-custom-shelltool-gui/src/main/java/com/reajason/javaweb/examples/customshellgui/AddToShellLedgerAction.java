package com.reajason.javaweb.examples.customshellgui;

import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;

/**
 * 结果区动作：「加入我的 Shell 列表」——把当前生成结果交给下游自己的数据结构。
 *
 * <p>按钮由 GUI 结果区自动渲染，未生成结果时自动置灰。
 */
public class AddToShellLedgerAction implements ResultAction {

    @Override
    public String label() {
        return "加入我的 Shell 列表";
    }

    @Override
    public void perform(DesktopMemShellGenerateResult result) {
        ShellLedger.addToMyShells(result);
    }
}

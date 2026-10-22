package com.reajason.javaweb.examples.customgui.gui;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.examples.customgui.shelltool.GodzillaSessionConfig;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 下游工具自己的"内存马台账"（示例用一个进程内列表，真实工具换成自己的列表模型/持久化）。
 *
 * <p>两个入口对应 GUI 提供的两种集成方式：
 * <ul>
 *   <li>{@link #recordGenerated}：{@code GuiExtension#onResultGenerated} 回调自动记录 —— 每次生成都进"生成历史"；</li>
 *   <li>{@link #addToMyShells}：结果区的"加入我的 Shell 列表"按钮手动挑结果。</li>
 * </ul>
 */
public final class ShellLedger {

    private static final List<Entry> HISTORY = Collections.synchronizedList(new ArrayList<Entry>());
    private static final List<Entry> SHELLS = Collections.synchronizedList(new ArrayList<Entry>());

    private ShellLedger() {
    }

    /**
     * 生成成功即记录（GUI 回调）。
     */
    public static void recordGenerated(DesktopMemShellGenerateResult result) {
        HISTORY.add(Entry.of(result));
    }

    /**
     * 用户点"加入我的 Shell 列表"时记录。
     */
    public static void addToMyShells(DesktopMemShellGenerateResult result) {
        SHELLS.add(Entry.of(result));
    }

    public static List<Entry> history() {
        return new ArrayList<Entry>(HISTORY);
    }

    public static List<Entry> myShells() {
        return new ArrayList<Entry>(SHELLS);
    }

    public static void clear() {
        HISTORY.clear();
        SHELLS.clear();
    }

    /**
     * 台账条目：只抽出下游关心的字段，连接信息由下游自己拼（这里认得自己的 GodzillaSession 配置）。
     */
    public static final class Entry {
        private final String server;
        private final String shellType;
        private final String shellTool;
        private final String shellClassName;
        private final String connectionInfo;

        private Entry(String server, String shellType, String shellTool, String shellClassName, String connectionInfo) {
            this.server = server;
            this.shellType = shellType;
            this.shellTool = shellTool;
            this.shellClassName = shellClassName;
            this.connectionInfo = connectionInfo;
        }

        private static Entry of(DesktopMemShellGenerateResult result) {
            MemShellResult memShell = result.getMemShellResult();
            ShellToolConfig config = memShell.getShellToolConfig();
            String connectionInfo;
            if (config instanceof GodzillaSessionConfig) {
                GodzillaSessionConfig toolConfig = (GodzillaSessionConfig) config;
                connectionInfo = "pass=" + toolConfig.getPass()
                        + " key=" + toolConfig.getKey()
                        + " " + toolConfig.getHeaderName() + "=" + toolConfig.getHeaderValue()
                        + " sessionKey=" + toolConfig.getSessionKey();
            } else {
                connectionInfo = config.getClass().getSimpleName();
            }
            return new Entry(memShell.getShellConfig().getServer(),
                    memShell.getShellConfig().getShellType(),
                    memShell.getShellConfig().getShellTool(),
                    memShell.getShellClassName(),
                    connectionInfo);
        }

        public String getServer() {
            return server;
        }

        public String getShellType() {
            return shellType;
        }

        public String getShellTool() {
            return shellTool;
        }

        public String getShellClassName() {
            return shellClassName;
        }

        /**
         * 下游自己拼的连接信息（示例里就是内存马的密码/密钥/请求头/会话 key）。
         */
        public String getConnectionInfo() {
            return connectionInfo;
        }

        @Override
        public String toString() {
            return server + "/" + shellType + " " + shellTool + " " + shellClassName + " (" + connectionInfo + ")";
        }
    }
}

package com.reajason.javaweb.woodpecker;

import me.gv7.woodpecker.plugin.IArg;
import me.gv7.woodpecker.plugin.IArgsUsageBinder;
import me.gv7.woodpecker.plugin.IHelper;
import me.gv7.woodpecker.plugin.IHelperPlugin;
import me.gv7.woodpecker.plugin.IHelperPluginCallbacks;
import me.gv7.woodpecker.plugin.InfoDetectorPlugin;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IPluginManagerCallbacks;
import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.plugin.IScanResult;
import me.gv7.woodpecker.plugin.IVulPlugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Woodpecker 框架侧对象的最小实现：插件接口都由框架提供，测试里补上这些桩，
 * 就能像框架那样「拿参数表格的默认值 → 调 doHelp → 收输出」跑完整条链路。
 */
public final class WoodpeckerStubs {

    private WoodpeckerStubs() {
    }

    /**
     * {@code IResultOutput}：保留前缀，便于断言输出里各类信息的位置关系。
     */
    public static final class ResultOutput implements IResultOutput {
        private final List<String> lines = new ArrayList<String>();

        @Override
        public void rawPrintln(String msg) {
            lines.add(msg);
        }

        @Override
        public void debugPrintln(String msg) {
            lines.add("[D] " + msg);
        }

        @Override
        public void infoPrintln(String msg) {
            lines.add("[*] " + msg);
        }

        @Override
        public void successPrintln(String msg) {
            lines.add("[+] " + msg);
        }

        @Override
        public void failPrintln(String msg) {
            lines.add("[-] " + msg);
        }

        @Override
        public void warningPrintln(String msg) {
            lines.add("[!] " + msg);
        }

        @Override
        public void errorPrintln(String msg) {
            lines.add("[x] " + msg);
        }

        @Override
        public void startPrintln(String msg) {
            lines.add("[>] " + msg);
        }

        @Override
        public void stopPrintln(String msg) {
            lines.add("[=] " + msg);
        }

        public List<String> getLines() {
            return lines;
        }

        public String text() {
            StringBuilder builder = new StringBuilder();
            for (String line : lines) {
                builder.append(line).append('\n');
            }
            return builder.toString();
        }

        /**
         * @return 首个命中前缀的行，便于断言「某类信息出现没出现」
         */
        public String firstLineContaining(String keyword) {
            for (String line : lines) {
                if (line.contains(keyword)) {
                    return line;
                }
            }
            return null;
        }

        public boolean hasLineContaining(String keyword) {
            return firstLineContaining(keyword) != null;
        }

        /**
         * @return 不带前缀、非空的原始输出行（打包产物就是这些行）
         */
        public List<String> rawLines() {
            List<String> raw = new ArrayList<String>();
            for (String line : lines) {
                if (!line.isEmpty() && !line.startsWith("[") && !line.startsWith("###")) {
                    raw.add(line);
                }
            }
            return raw;
        }
    }

    public static final class Arg implements IArg {
        private String name;
        private int type;
        private String defaultValue;
        private List<String> enumValue;
        private boolean required;
        private String description;

        @Override
        public void setName(String name) {
            this.name = name;
        }

        @Override
        public void setType(int type) {
            this.type = type;
        }

        @Override
        public void setDefaultValue(String defaultValue) {
            this.defaultValue = defaultValue;
        }

        @Override
        public void setEnumValue(List<String> enumValue) {
            this.enumValue = enumValue;
        }

        @Override
        public void setRequired(boolean is) {
            this.required = is;
        }

        @Override
        public void setDescription(String desc) {
            this.description = desc;
        }

        public String getName() {
            return name;
        }

        public int getType() {
            return type;
        }

        public String getDefaultValue() {
            return defaultValue;
        }

        public List<String> getEnumValue() {
            return enumValue;
        }

        public boolean isRequired() {
            return required;
        }

        public String getDescription() {
            return description;
        }
    }

    public static final class ArgsUsageBinder implements IArgsUsageBinder {
        private List<IArg> argsList = new ArrayList<IArg>();
        private String usage;

        @Override
        public void setArgsList(List<IArg> argsList) {
            this.argsList = argsList;
        }

        @Override
        public void setUsage(String usage) {
            this.usage = usage;
        }

        public List<IArg> getArgsList() {
            return argsList;
        }

        public String getUsage() {
            return usage;
        }

        /**
         * 表格默认值 → doHelp 的参数 Map，等同用户在界面上原样点执行。
         */
        public Map<String, Object> defaultArgs() {
            Map<String, Object> args = new LinkedHashMap<String, Object>();
            for (IArg arg : argsList) {
                Arg stub = (Arg) arg;
                args.put(stub.getName(), stub.getDefaultValue());
            }
            return args;
        }

        /**
         * 框架界面里 Args 文本框的预填内容：默认值非空的参数（即必填项）才会预填，其余靠用户自己写。
         */
        public Map<String, Object> prefilledArgs() {
            Map<String, Object> args = new LinkedHashMap<String, Object>();
            for (IArg arg : argsList) {
                Arg stub = (Arg) arg;
                if (stub.isRequired()) {
                    args.put(stub.getName(), stub.getDefaultValue());
                }
            }
            return args;
        }
    }

    public static final class PluginHelper implements IPluginHelper {
        @Override
        public IArg createArg() {
            return new Arg();
        }

        @Override
        public IArgsUsageBinder createArgsUsageBinder() {
            return new ArgsUsageBinder();
        }

        @Override
        public IScanResult createScanResult() {
            return null;
        }

        @Override
        public String getThrowableInfo(Throwable e) {
            return e == null ? "" : e.toString();
        }
    }

    /**
     * 框架加载插件时回调的第一个对象：插件在这里把自己登记成辅助插件。
     */
    public static final class PluginManagerCallbacks implements IPluginManagerCallbacks {
        private final List<IHelperPlugin> helperPlugins = new ArrayList<IHelperPlugin>();

        @Override
        public void registerInfoDetectorPlugin(InfoDetectorPlugin plugin) {
            throw new UnsupportedOperationException("本插件不提供信息探测模块");
        }

        @Override
        public void registerVulPlugin(IVulPlugin plugin) {
            throw new UnsupportedOperationException("本插件不提供漏洞模块");
        }

        @Override
        public void registerHelperPlugin(IHelperPlugin helperPlugin) {
            helperPlugins.add(helperPlugin);
        }

        public List<IHelperPlugin> getHelperPlugins() {
            return helperPlugins;
        }
    }

    /**
     * 框架加载辅助插件时回调的第二个对象：插件在这里报名字/版本并登记页签。
     */
    public static final class HelperPluginCallbacks implements IHelperPluginCallbacks {
        private final IPluginHelper pluginHelper = new PluginHelper();
        private final List<IHelper> helpers = new ArrayList<IHelper>();
        private String name;
        private String version;
        private String author;
        private String description;
        private String path;

        @Override
        public void setHelperPluginName(String name) {
            this.name = name;
        }

        @Override
        public void setHelperPluginVersion(String version) {
            this.version = version;
        }

        @Override
        public void setHelperPluginPath(String path) {
            this.path = path;
        }

        @Override
        public void setHelperPluginAutor(String autor) {
            this.author = autor;
        }

        @Override
        public void setHelperPluginDescription(String description) {
            this.description = description;
        }

        @Override
        public IPluginHelper getPluginHelper() {
            return pluginHelper;
        }

        @Override
        public void registerHelper(List<IHelper> helperList) {
            helpers.addAll(helperList);
        }

        public List<IHelper> getHelpers() {
            return helpers;
        }

        public IHelper helper(String tabCaption) {
            for (IHelper helper : helpers) {
                if (tabCaption.equals(helper.getHelperTabCaption())) {
                    return helper;
                }
            }
            throw new AssertionError("没有注册页签：" + tabCaption + "，已注册：" + captions());
        }

        public List<String> captions() {
            List<String> captions = new ArrayList<String>();
            for (IHelper helper : helpers) {
                captions.add(helper.getHelperTabCaption());
            }
            return captions;
        }

        public String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }

        public String getAuthor() {
            return author;
        }

        public String getDescription() {
            return description;
        }

        public String getPath() {
            return path;
        }
    }
}

package com.reajason.javaweb.woodpecker;

import me.gv7.woodpecker.plugin.IArg;
import me.gv7.woodpecker.plugin.IArgsUsageBinder;
import me.gv7.woodpecker.plugin.IPluginHelper;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Woodpecker 参数的读写。
 *
 * <p>参数一律用 STRING 类型：框架界面里参数是用户手写的「参数名=值」文本行（必填项会按默认值预填），
 * 用 STRING 可以避开框架按 Boolean/Int 解析文本带来的报错，取值由插件自己宽松解析。
 */
final class Args {

    private Args() {
    }

    static IArgsUsageBinder binder(IPluginHelper pluginHelper, List<IArg> args, String usage) {
        IArgsUsageBinder binder = pluginHelper.createArgsUsageBinder();
        binder.setArgsList(args);
        binder.setUsage(usage);
        return binder;
    }

    /**
     * 默认值为空的参数不能标必填：留空表示「由生成器随机」（密码、密钥、类名），
     * 标了必填框架会按必填校验，留空就执行不了。
     */
    static IArg arg(IPluginHelper pluginHelper, String name, String defaultValue, String description) {
        IArg arg = pluginHelper.createArg();
        arg.setName(name);
        arg.setType(IArg.ARG_TYPE_STRING);
        arg.setDefaultValue(defaultValue);
        arg.setRequired(defaultValue != null && !defaultValue.trim().isEmpty());
        arg.setDescription(description);
        return arg;
    }

    /**
     * 单元格取值转字符串；参数缺失（老版本框架/用户删了行）时返回兜底值。
     */
    static String str(Map<String, Object> args, String name, String fallback) {
        Object value = args == null ? null : args.get(name);
        if (value == null) {
            return fallback;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? fallback : text;
    }

    /**
     * 布尔参数：表格里只能填文本，所以除了 true/false 还认 1/0、yes/no、on/off（大小写不敏感）。
     *
     * @return 没填或认不出来时返回 null —— 由调用方决定是退回默认值还是提示用户改错
     */
    static Boolean parseFlag(Map<String, Object> args, String name) {
        String text = str(args, name, "");
        if (text.isEmpty()) {
            return null;
        }
        String normalized = text.toLowerCase(Locale.ROOT);
        if ("true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized)
                || "y".equals(normalized) || "on".equals(normalized)) {
            return Boolean.TRUE;
        }
        if ("false".equals(normalized) || "0".equals(normalized) || "no".equals(normalized)
                || "n".equals(normalized) || "off".equals(normalized)) {
            return Boolean.FALSE;
        }
        return null;
    }
}

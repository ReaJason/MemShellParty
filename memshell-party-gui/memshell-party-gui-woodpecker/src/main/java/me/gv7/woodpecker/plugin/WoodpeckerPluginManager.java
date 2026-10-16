package me.gv7.woodpecker.plugin;

import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.woodpecker.CatalogHelper;
import com.reajason.javaweb.woodpecker.MemShellHelper;
import com.reajason.javaweb.woodpecker.ProbeShellHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * Woodpecker 插件入口。类名与包名是框架的约定：框架扫描 plugin/ 目录下的 jar，
 * 反射加载 {@code me.gv7.woodpecker.plugin.WoodpeckerPluginManager} 并调用这两个方法，改名插件不会被加载。
 *
 * <p>生成逻辑全部来自 MemShellParty 的 GUI SDK（目录、表单联动、校验、生成、打包、结果信息行），
 * 本模块只做 Woodpecker 参数表格 ↔ SDK 表单状态的翻译与文本输出。
 */
public class WoodpeckerPluginManager implements IPluginManager, IHelperPlugin {

    @Override
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks pluginManagerCallbacks) {
        pluginManagerCallbacks.registerHelperPlugin(this);
    }

    @Override
    public void HelperPluginMain(IHelperPluginCallbacks helperPluginCallbacks) {
        helperPluginCallbacks.setHelperPluginName("MemShellParty");
        // 与依赖的 GUI SDK 同一次构建，版本一致
        helperPluginCallbacks.setHelperPluginVersion(AppVersion.get());
        helperPluginCallbacks.setHelperPluginAutor("ReaJason");
        helperPluginCallbacks.setHelperPluginDescription(
                "内存马 / 探测马生成器：服务端 × 工具 × 挂载类型 × 打包方式，与桌面端、Web 端同一套生成引擎");

        IPluginHelper pluginHelper = helperPluginCallbacks.getPluginHelper();
        List<IHelper> helpers = new ArrayList<IHelper>();
        helpers.add(new MemShellHelper(pluginHelper));
        helpers.add(new ProbeShellHelper(pluginHelper));
        helpers.add(new CatalogHelper(pluginHelper));
        helperPluginCallbacks.registerHelper(helpers);
    }
}

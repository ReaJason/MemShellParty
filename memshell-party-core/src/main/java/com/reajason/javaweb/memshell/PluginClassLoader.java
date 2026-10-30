package com.reajason.javaweb.memshell;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * 标记启动期插件类加载器。首版有意使用父优先与单加载器，不提供插件间依赖隔离。
 */
final class PluginClassLoader extends URLClassLoader {
    PluginClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
    }
}

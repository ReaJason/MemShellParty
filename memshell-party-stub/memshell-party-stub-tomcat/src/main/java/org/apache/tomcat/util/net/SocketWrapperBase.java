package org.apache.tomcat.util.net;

/**
 * Tomcat {@code org.apache.tomcat.util.net.SocketWrapperBase} 的生成期桩：只作 UpgradeProtocol
 * 的形参类型出现。真实 Tomcat 里是带类型参数的 abstract class，桩保持泛型与 abstract，否则
 * {@code SocketWrapperBase<?>} 这种实参写不出来 / 生成的描述符对不上。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public abstract class SocketWrapperBase<E> {
}

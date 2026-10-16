package org.apache.coyote.http11.upgrade;

/**
 * Tomcat {@code org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler} 的生成期桩：
 * 只作 UpgradeProtocol#getInternalUpgradeHandler 的返回类型出现，模板不调用它的方法，所以不声明成员。
 * <p>
 * 真实 Tomcat 里它还继承了 javax.servlet.http.HttpUpgradeHandler，但本仓库的 servlet-api 是 3.0.1
 * （没有这个接口，3.1 才加），而生成期只需要类型名 —— 少了这层父接口不影响生成的字节码。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public interface InternalHttpUpgradeHandler {
}

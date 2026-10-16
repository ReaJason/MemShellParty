package org.apache.coyote;

import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

/**
 * Tomcat {@code org.apache.coyote.UpgradeProtocol} 的生成期桩：Upgrade 类模板实现的就是它，
 * 六个方法的签名必须与 Tomcat 逐一对齐（少一个，生成的类在目标容器上就是抽象方法未实现）。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public interface UpgradeProtocol {

    String getHttpUpgradeName(boolean isSSLEnabled);

    byte[] getAlpnIdentifier();

    String getAlpnName();

    Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter);

    InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request);

    boolean accept(Request request);
}

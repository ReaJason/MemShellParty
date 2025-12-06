package org.apache.coyote;

import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
public interface UpgradeProtocol {
    public String getHttpUpgradeName(boolean isSSLEnabled);

    public byte[] getAlpnIdentifier();

    public String getAlpnName();

    public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter);

    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request);

    public boolean accept(Request request);
}

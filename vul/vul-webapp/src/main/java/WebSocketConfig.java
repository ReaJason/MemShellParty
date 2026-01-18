import javax.websocket.Endpoint;
import javax.websocket.server.ServerApplicationConfig;
import javax.websocket.server.ServerEndpointConfig;
import java.util.HashSet;
import java.util.Set;

public class WebSocketConfig implements ServerApplicationConfig {
    @Override
    public Set<ServerEndpointConfig> getEndpointConfigs(Set<Class<? extends Endpoint>> scannedEndpointClasses) {
        Set<ServerEndpointConfig> result = new HashSet<ServerEndpointConfig>();
        ServerEndpointConfig config = ServerEndpointConfig.Builder
                .create(EmptyWebSocketEndpoint.class, "/empty-ws")
                .build();

        result.add(config);
        System.out.println("websocket init success");
        return result;
    }

    @Override
    public Set<Class<?>> getAnnotatedEndpointClasses(Set<Class<?>> scanned) {
        return scanned;
    }
}
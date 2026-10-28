package com.ibm.ws.webcontainer.managedobject;

import com.ibm.ws.webcontainer.webapp.WebApp;

import java.util.EventListener;

public class ManagedObjectListenerWrapper {
    private final Object listener;
    private final Object webApp;

    public ManagedObjectListenerWrapper(EventListener listener, WebApp webApp) {
        this.listener = listener;
        this.webApp = webApp;
    }

    public Object getListener() {
        return listener;
    }

    public Object getWebApp() {
        return webApp;
    }
}

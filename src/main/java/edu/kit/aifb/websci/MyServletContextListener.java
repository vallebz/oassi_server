package edu.kit.aifb.websci;

import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.servlet.ServletContainer;
// import org.glassfish.jersey.server.ResourceConfig;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.annotation.WebListener;

@WebListener
public class MyServletContextListener implements ServletContextListener {

    ServletContext ctx;
    

    /**
     * On startup of context (on server up), register your servlets.
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ctx = sce.getServletContext();
        ServletRegistration sr = ctx.addServlet("MyExampleServlet", ServletContainer.class);
        sr.addMapping("/*"); // no idea why wildcard is needed, but it is what it is.
        sr.setInitParameter(ServerProperties.PROVIDER_PACKAGES, this.getClass().getPackage().toString());
    }
}


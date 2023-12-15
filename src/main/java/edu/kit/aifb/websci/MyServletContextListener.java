package edu.kit.aifb.websci;

import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.servlet.ServletContainer;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.annotation.WebListener;

import jakarta.servlet.FilterRegistration;
import jakarta.ws.rs.HttpMethod;

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
        FilterRegistration fr;
        // Register and configure filter to handle CORS requests
        fr = ctx.addFilter("cross-origin", org.eclipse.jetty.servlets.CrossOriginFilter.class.getName());
        fr.setInitParameter(org.eclipse.jetty.servlets.CrossOriginFilter.ALLOWED_METHODS_PARAM,
                HttpMethod.GET + "," + HttpMethod.PUT + "," + HttpMethod.POST + "," + HttpMethod.DELETE + "," + HttpMethod.OPTIONS + "," + HttpMethod.HEAD);
        fr.setInitParameter(org.eclipse.jetty.servlets.CrossOriginFilter.ALLOWED_HEADERS_PARAM, "*");
        fr.setInitParameter(org.eclipse.jetty.servlets.CrossOriginFilter.EXPOSED_HEADERS_PARAM , "*");
        fr.addMappingForUrlPatterns(null, true, "/*");
    }
}

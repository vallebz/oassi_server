package edu.kit.aifb.websci;

import java.io.*;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import jakarta.ws.rs.core.NewCookie.SameSite;

import org.apache.jena.graph.Graph;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.shacl.ShaclValidator;
import org.apache.jena.shacl.Shapes;
import org.apache.jena.shacl.ValidationReport;
import org.apache.jena.shacl.lib.ShLib;



@Path("/") // Specify the URL pattern for the servlet. Remember that this is relative to
// the application path defined in `pom.xml`
public class VerServlet {


    String path_VPshape = "./src/data/shapes/vp_shape.ttl";
    String resUrl = "http://localhost:8080/oassi-verifier/resource";

    private static Map<String, Boolean> sessionIds = new ConcurrentHashMap<>();

    static {
        sessionIds.put("SessionTrue", true);
    }

    @Context
    private HttpHeaders headers;

    @GET
    @Path("/resource")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource() {

        Map<String, Cookie> cookies = headers.getCookies();
        String sessionId;

        // If no (authorized) session cookie is provided, return 401 Unauthorized, 
        //        deliver a session cookie and an Access Request URI

        if (!cookies.containsKey("JSESSIONID") || cookies.isEmpty()) {
            sessionId = UUID.randomUUID().toString();
            NewCookie newCookie = new NewCookie.Builder("JSESSIONID")
                    .path("/")
                    .maxAge(3600)
                    .value(sessionId)
                    .secure(true)
                    .httpOnly(true)
                    .sameSite(SameSite.STRICT)
                    .build();
            SessionService.setSessionId(sessionId, false);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .link("http://localhost:8080/verifier/auth?res=base64("+ Base64.getEncoder().encodeToString(resUrl.getBytes()) +")", "OID4VC-access-request")
                    .header("Content-Type", "text/html")
                    .cookie(newCookie)
                    .build();
        }

        // If session cookie is provided, check for authorization and return 200 OK with resource 
        if (SessionService.getSessionId(cookies.get("JSESSIONID").getValue()) == false) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    // .entity("HTTP 401 Unauthorized\nSession cookie provided but not authorized.")
                    .header("Content-Type", "text/html")
                    .build();
        }
        return Response.ok()
                .entity("cookies contain AUTHORIZED JSESSIONID " + cookies.get("JSESSIONID"))
                .header("Content-Type", "text/html")
                .build();
    }

    @GET
    @Path("/request")
    @Produces(MediaType.TEXT_PLAIN)
    public Response authRequest() {

        return Response.ok()
                .entity("HTTP 200 OK\nAccess Request URI received.")
                .header("Content-Type", "text/html")
                .build();

    }
    
    /* Session Service */
    public static class SessionService {

        public static Boolean getSessionId(String sessionId) {
            boolean auth_bool = sessionIds.get(sessionId);
            System.out.println("Session ID checked: " + sessionId + " is authorized: " + auth_bool);
            return auth_bool;
            
        }

        public static void setSessionId(String sessionId, Boolean auth_bool) {
            sessionIds.put(sessionId, auth_bool);
            System.out.println("Session ID added: " + sessionId + " is authorized: " + auth_bool);
        }
    }


    // Read file content and return as string
    public String readFile(String filepath) {
        String content = null;
        File file = new File(filepath);
        FileReader reader = null;
        try {
            reader = new FileReader(file);
            char[] chars = new char[(int) file.length()];
            reader.read(chars);
            content = new String(chars);
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(content);
        return content;
    }

    // Validate the graph against the shape using SHACL
    public Boolean validateShape(String shapePath, String graph) {
        String SHAPES = readFile(shapePath);
        // String DATA = readFile(graphPath);
        Model ShapesModel = ModelFactory.createDefaultModel();
        try (StringReader stringReader = new StringReader(SHAPES)) {
            // Parse the RDF data into the model
            RDFDataMgr.read(ShapesModel, stringReader, null, Lang.TTL);
        }
        Model DataModel = ModelFactory.createDefaultModel();
        try (StringReader stringReader = new StringReader(graph)) {
            // Parse the RDF data into the model
            RDFDataMgr.read(DataModel, stringReader, null, Lang.TTL);
        }

        Graph shapesGraph = ShapesModel.getGraph();
        Graph dataGraph = DataModel.getGraph();

        Shapes shapes = Shapes.parse(shapesGraph);

        ValidationReport report = ShaclValidator.get().validate(shapes, dataGraph);
        ShLib.printReport(report);
        System.out.println();
        RDFDataMgr.write(System.out, report.getModel(), Lang.TTL);
        boolean conforms = report.conforms();
        return conforms;
    }
    
    // Dummy method - signatures need to be checked
    public boolean validateSignature(String resource, String signatureValue) {
        // Dummy method - signatures need to be checked
        return true;
    }

}

/**** Credential validation ****/
// if (validateShape(path_VPshape, authString)) {
// if (validateSignature("Resources", "Signature Value")) {
// return Response.ok()
// .entity("HTTP 200 OK\nAuthorized - Credential matches shape.")
// .header("Content-Type", "text/html")
// .build();
// }
// }
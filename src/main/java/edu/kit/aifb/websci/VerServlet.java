package edu.kit.aifb.websci;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.NewCookie.SameSite;

import org.apache.jena.base.Sys;
import org.apache.jena.graph.Graph;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.shacl.ShaclValidator;
import org.apache.jena.shacl.Shapes;
import org.apache.jena.shacl.ValidationReport;
import org.apache.jena.shacl.lib.ShLib;

@Path("/") // Specifies the base URL pattern for this servlet.
public class VerServlet {

    // Maps session IDs to their respective Verifiable Presentations.
    private static ConcurrentHashMap<String, ArrayList<Model>> session_presentations = new ConcurrentHashMap<>();

    // Maps server resources to their respective SHACL shapes.
    private static ConcurrentHashMap<String, ArrayList<Model>> resource_shapes = new ConcurrentHashMap<>();

    static {
        try {
            // Load SHACL shapes from a file and add them to the resource "resource".
            String shapeContent = new String(Files.readAllBytes(Paths.get("./src/data/shapes/example_vp_shape.ttl")));
            AuthService.createResource("resource");
            AuthService.addShapeToResource("resource", parseRDF(shapeContent, Lang.TTL));

            // Create a session when the servlet is initialized.
            SessionService.createSession();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @GET
    @Path("/resource")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource(@Context UriInfo uriInfo, @Context HttpHeaders headers) {

        String path = uriInfo.getPath(); // Gets the requested resource path.
        Map<String, Cookie> cookies = headers.getCookies(); // Retrieves the cookies from the request.

        // If no session cookie is provided or the session is unauthorized, return 401
        // Unauthorized.
        if (!cookies.containsKey("JSESSIONID") || cookies.isEmpty()) {
            String sessionID = SessionService.createSession(); // Create a new session.
            NewCookie newCookie = new NewCookie.Builder("JSESSIONID")
                    .path("/")
                    .maxAge(3600)
                    .value(sessionID)
                    .secure(true)
                    .httpOnly(true)
                    .sameSite(SameSite.STRICT)
                    .build();

            return Response.status(Response.Status.UNAUTHORIZED)
                    .link("http://localhost:8080/auth/request?res="
                            + Base64.getEncoder().encodeToString(path.getBytes()), "OID4VC-access-request")
                    .header("Content-Type", "text/html")
                    .cookie(newCookie)
                    .build();
        }

        // If the session is not authorized for the requested resource, return 401
        // Unauthorized.
        if (!SessionService.isSessionAuthorizedForResource(cookies.get("JSESSIONID").getValue(), path)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .link("http://localhost:8080/auth/request?res="
                            + Base64.getEncoder().encodeToString(path.getBytes()), "OID4VC-access-request")
                    .header("Content-Type", "text/html")
                    .build();
        }

        // If the session is authorized, return the requested resource.
        return Response.ok()
                .entity("Congratulations, here is your requested resource!\nAUTHORIZED JSESSIONID "
                        + cookies.get("JSESSIONID").getValue())
                .header("Content-Type", "text/html")
                .build();
    }

    @GET
    @Path("/auth/request")
    @Produces("text/turtle")
    public Response authRequest(@QueryParam("res") String base64EncodedResource, @Context HttpHeaders headers) {

        // If the resource parameter is missing or invalid, return 400 Bad Request.
        if (base64EncodedResource == null || base64EncodedResource.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error: No resource provided.")
                    .build();
        }

        // Decode the base64-encoded resource path.
        byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedResource);
        String decodedResource = new String(decodedBytes);

        // If the resource does not exist, return 404 Not Found.
        if (AuthService.getShapesForResource(decodedResource) == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .build();
        }

        // Collect all SHACL shapes for the resource and return them.
        StringBuilder allShapes = new StringBuilder();
        ArrayList<Model> tmp_shapes = AuthService.getShapesForResource(decodedResource);
        for (Model shape : tmp_shapes) {
            StringWriter writer = new StringWriter();
            shape.write(writer, "TURTLE");
            allShapes.append(writer.toString());
            allShapes.append("\n\n");
        }

        return Response.ok(allShapes.toString())
                .header("Content-Type", "text/turtle")
                .link("http://localhost:8080/auth/present", "OID4VC-access-presentation")
                .build();
    }

    @POST
    @Path("/auth/present")
    @Consumes("text/plain")
    public Response authPresent(@Context HttpServletRequest request, @Context HttpHeaders headers, String input) {

        Map<String, Cookie> cookies = headers.getCookies(); // Retrieve the cookies from the request.

        // If no session cookie is provided, return 400 Bad Request.
        if (cookies.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No session cookie provided")
                    .build();
        }

        String sessionId = cookies.get("JSESSIONID").getValue(); // Retrieve the session ID from the cookie.
        if (sessionId == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No session cookie provided")
                    .build();
        }

        // Read the request body containing the Verifiable Presentation (VP).
        String vpString;
        vpString = input;

        // Parse the VP from the request body into a Jena Model.
        Model vpModel = parseRDF(vpString, Lang.TURTLE);

        // Add the VP to the session.
        ArrayList<Model> tmp_presentations = SessionService.getPresentationsForSession(sessionId);
        tmp_presentations.add(vpModel);
        SessionService.addToSession(sessionId, tmp_presentations);

        return Response.ok()
                .entity("Presentation added to session " + sessionId)
                .header("Content-Type", "text/html")
                .build();
    }

    // SessionService: Manages sessions and their associated verifiable
    // presentations.
    public static class SessionService {

        // Creates a new session and returns its session ID.
        public static String createSession() {
            String sessionId = UUID.randomUUID().toString();
            ArrayList<Model> emptyList = new ArrayList<>();
            session_presentations.put(sessionId, emptyList);
            return sessionId;
        }

        // Adds a list of Verifiable Presentations to a session.
        public static void addToSession(String sessionID, ArrayList<Model> verifiablePresentation) {
            session_presentations.put(sessionID, verifiablePresentation);
        }

        // Retrieves all Verifiable Presentations for a given session.
        public static ArrayList<Model> getPresentationsForSession(String sessionID) {
            return session_presentations.get(sessionID);
        }

        // Checks if a session is authorized to access a specific resource.
        public static boolean isSessionAuthorizedForResource(String sessionID, String path) {
            ArrayList<Model> presentationArrayList = session_presentations.get(sessionID);
            ArrayList<Model> shapeArrayList = resource_shapes.get(path);
            for (Model presentation : presentationArrayList) {
                for (Model shape : shapeArrayList) {
                    if (AuthService.validateShape(shape, presentation)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    // AuthService: Manages resources and their associated SHACL shapes.
    public static class AuthService {

        // Creates a new resource and associates an empty list of shapes with it.
        public static void createResource(String resourcePath) {
            ArrayList<Model> emptyList = new ArrayList<>();
            resource_shapes.put(resourcePath, emptyList);
        }

        // Adds a SHACL shape to a resource.
        public static void addShapeToResource(String resourcePath, Model shape) {
            ArrayList<Model> shapes = resource_shapes.get(resourcePath);
            shapes.add(shape);
            resource_shapes.put(resourcePath, shapes);
        }

        // Retrieves all SHACL shapes associated with a resource.
        public static ArrayList<Model> getShapesForResource(String resourcePath) {
            return resource_shapes.get(resourcePath);
        }

        // Validates a graph against a SHACL shape using the Jena SHACL API.
        public static boolean validateShape(Model shape, Model graph) {

            Graph shapeGraph = shape.getGraph();
            Graph dataGraph = graph.getGraph();

            Shapes shapesSHACL = Shapes.parse(shapeGraph);

            ValidationReport report = ShaclValidator.get().validate(shapesSHACL, dataGraph);
            ShLib.printReport(report);
            RDFDataMgr.write(System.out, report.getModel(), Lang.TTL);
            return report.conforms(); // Returns true if the graph conforms to the shape.
        }
    }

    // Utility method to read the content of a file and return it as a string.
    public String readFile(String filepath) {
        String content = null;
        File file = new File(filepath);
        try (FileReader reader = new FileReader(file)) {
            char[] chars = new char[(int) file.length()];
            reader.read(chars);
            content = new String(chars);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    // Dummy method to verify the signature of a resource.
    public boolean verifySignature(String resource, String signatureValue) {
        // Signature verification assumed to be successful.
        return true;
    }

    // Parses an RDF string into a Jena Model.
    public static Model parseRDF(String rdfString, Lang lang) {

        Model model = ModelFactory.createDefaultModel();
        try (StringReader stringReader = new StringReader(rdfString)) {
            RDFDataMgr.read(model, stringReader, null, lang);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return model;
    }
}
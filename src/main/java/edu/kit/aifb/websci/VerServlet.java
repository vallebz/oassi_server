package edu.kit.aifb.websci;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.PathParam;
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
            // For DEMO purposes, we load a SHACL shape from a file and add it to the
            // resources
            // we have on the solid pod container
            // "https://sme.solid.aifb.kit.edu/bookings/".
            String shapeContent = new String(Files.readAllBytes(Paths.get("./src/data/shapes/example_vp_shape.ttl")));
            AuthService.createResource("0.ttl");
            AuthService.createResource("readme.ttl");
            AuthService.addShapeToResource("0.ttl", parseRDF(shapeContent, Lang.TTL));
            AuthService.addShapeToResource("readme.ttl", parseRDF(shapeContent, Lang.TTL));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Checks if the nonce is present and not empty.
    private boolean hasNonce(String nonce) {
        return nonce != null && !nonce.isEmpty();
    }

    // Checks if the session cookie is present.
    private boolean hasSessionCookie(Map<String, Cookie> cookies) {
        return !cookies.isEmpty() && cookies.containsKey("JSESSIONID");
    }

    // Validates the session based on equivalency of nonce and session cookie.
    private boolean isValidSession(String nonce, Map<String, Cookie> cookies) {
        if (hasNonce(nonce) && hasSessionCookie(cookies)) {
            return nonce.equals(cookies.get("JSESSIONID").getValue());
        }
        return hasNonce(nonce) || hasSessionCookie(cookies);
    }

    // Retrieves the session ID from nonce or cookies.
    private String getSessionID(String nonce, Map<String, Cookie> cookies) {
        if (hasNonce(nonce)) {
            return nonce;
        }
        if (hasSessionCookie(cookies)) {
            return cookies.get("JSESSIONID").getValue();
        }
        return null;
    }

    @GET
    @Path("/getResource/{subPath: [[a-zA-Z0-9_/.]+[a-zA-Z0-9_/.]*]*}")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource(@Context UriInfo uriInfo, @Context HttpHeaders headers,
            @PathParam("subPath") String subPath) {
        String nonce = uriInfo.getQueryParameters().getFirst("nonce"); // Retrieve the nonce parameter from the request.
        Map<String, Cookie> cookies = headers.getCookies(); // Retrieves the cookies from the request.

        // If the resource parameter is missing or invalid, return 400 Bad Request.
        if (subPath == null || subPath.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error: No resource provided.")
                    .build();
        }
        String file = "https://sme.solid.aifb.kit.edu/bookings/" + subPath;

        // If the session is not valid, create a new session and return 401
        // Unauthorized.
        if (!isValidSession(nonce, cookies)) {
            String sessionID = SessionService.createSession(); // Create a new session.
            NewCookie sessionCookie = new NewCookie.Builder("JSESSIONID")
                    .path("/")
                    .maxAge(3600)
                    .value(sessionID)
                    .secure(true)
                    .httpOnly(true)
                    .sameSite(SameSite.STRICT)
                    .build();

            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Error: Invalid or missing session ID.")
                    .link("http://localhost:8080/auth/request?res="
                            + Base64.getEncoder().encodeToString(subPath.getBytes())
                            + "&nonce=" + sessionID, "OID4VC-access-request")
                    .cookie(sessionCookie)
                    .build();
        }

        String sessionID = getSessionID(nonce, cookies);

        // If the session is not authorized for the requested resource, return 401
        // Unauthorized.
        if (!SessionService.isSessionAuthorizedForResource(sessionID, subPath)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Error: Session ID is not authorized to access this resource. Please authenticate with your credentials.")
                    .link("http://localhost:8080/auth/request?res="
                            + Base64.getEncoder().encodeToString(subPath.getBytes()), "OID4VC-access-request")
                    .header("Content-Type", "text/html")
                    .build();
        }

        try {
            // Create a URL connection
            URL url = new URL(file);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // Read the response
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String content = in.lines().collect(Collectors.joining("\n"));

            // Close the connections
            in.close();
            connection.disconnect();

            // If the session is authorized, return the requested resource.
            return Response.ok()
                    .entity(content)
                    .header("Content-Type", "text/html")
                    .build();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Fehler beim Abrufen der Ressource: " + e.getMessage())
                    .header("Content-Type", "text/html")
                    .build();
        }
    }

    @GET
    @Path("/auth/request/{subPath: [[a-zA-Z0-9_/.]+[a-zA-Z0-9_/.]*]*}")
    @Produces("text/turtle")
    public Response authRequest(@Context UriInfo uriInfo, @PathParam("subPath") String subPath) {

        // If the resource parameter is missing or invalid, return 400 Bad Request.
        if (subPath == null || subPath.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error: No resource provided.")
                    .build();
        }

        // If the resource does not exist, return 404 Not Found.
        if (AuthService.getShapesForResource(subPath) == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .build();
        }

        // Collect all SHACL shapes for the resource and return them.
        StringBuilder allShapes = new StringBuilder();
        ArrayList<Model> tmp_shapes = AuthService.getShapesForResource(subPath);
        for (Model shape : tmp_shapes) {
            StringWriter writer = new StringWriter();
            shape.write(writer, "TURTLE");
            allShapes.append(writer.toString());
            allShapes.append("\n\n");
        }

        return Response.ok(allShapes.toString())
                .header("Content-Type", "text/turtle")
                .link("http://localhost:8080/auth/present/" + subPath, "OID4VC-access-presentation")
                .build();
    }

    @POST
    @Path("/auth/present")
    @Consumes("text/plain")
    public Response authPresent(@Context UriInfo uriInfo, @Context HttpHeaders headers,
            @Context HttpServletRequest request, String input) {

        Map<String, Cookie> cookies = headers.getCookies(); // Retrieves the cookies from the request.
        String nonce = uriInfo.getQueryParameters().getFirst("nonce");

        // If the session is not valid, return 400 Bad Request.
        if (!isValidSession(nonce, cookies)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid or no sessionID provided")
                    .build();
        }

        String sessionID = getSessionID(nonce, cookies);

        // Read the request body containing the Verifiable Presentation (VP).
        String vpString = input;

        // Parse the VP from the request body into a Jena Model.
        Model vpModel = parseRDF(vpString, Lang.TURTLE);

        // Add the VP to the session.
        ArrayList<Model> tmp_presentations = SessionService.getPresentationsForSession(sessionID);
        tmp_presentations.add(vpModel);
        SessionService.addToSession(sessionID, tmp_presentations);

        return Response.ok()
                .entity("Presentation added to session " + sessionID)
                .header("Content-Type", "text/html")
                .build();
    }

    // Returns all sessionIDs.
    @GET
    @Path("/allSessions")
    @Consumes("text/plain")
    public Response allSessions() {
        return Response.ok()
                .entity(session_presentations.toString())
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

        // Adds a list of Verifiable Presentations to a session ID.
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

            if (presentationArrayList == null || shapeArrayList == null) {
                return false;
            }

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
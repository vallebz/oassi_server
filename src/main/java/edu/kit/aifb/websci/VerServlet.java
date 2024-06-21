package edu.kit.aifb.websci;

import java.io.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.apache.jena.graph.Graph;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.shacl.ShaclValidator;
import org.apache.jena.shacl.Shapes;
import org.apache.jena.shacl.ValidationReport;
import org.apache.jena.shacl.lib.ShLib;



@Path("/resource") // Specify the URL pattern for the servlet. Remember that this is relative to
// the application path defined in `pom.xml`
public class VerServlet {


    String path_VPshape = "./src/data/shapes/vp_shape.ttl";

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource(@HeaderParam("authn-data") String authString) {

        // If no credentials are provided, return 401 and ask for matching credentials
        if (authString == null || authString.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("HTTP 401 Unauthorized\nProvide credential matching shape defined in www-authenticate header.")
                    .header("www-authenticate",
                            readFile(path_VPshape))
                    .header("Content-Type", "text/html")
                    .build();
        }


        // If credentials are provided, validate them and return 200 if they match the shape
        if (validateShape(path_VPshape, authString)) {
            if (validateSignature("Resources", "Signature Value")) {
                return Response.ok()
                        .entity("HTTP 200 OK\nAuthorized - Credential matches shape.")
                        .header("Content-Type", "text/html")
                        .build();
            }
        }

        // In any other case, return 401 and ask for a matching credential
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("HTTP 401 Unauthorized\nProvide credential matching shape defined in www-authenticate header.")
                .header("www-authenticate",
                        readFile(path_VPshape))
                .header("Content-Type", "text/html")
                .build();

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


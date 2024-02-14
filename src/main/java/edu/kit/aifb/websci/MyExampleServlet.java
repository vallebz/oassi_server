package edu.kit.aifb.websci;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;

import org.apache.jena.graph.Graph;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.shacl.ShaclValidator;
import org.apache.jena.shacl.Shapes;
import org.apache.jena.shacl.ValidationReport;
import org.apache.jena.shacl.lib.ShLib;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/resource") // Specify the URL pattern for the servlet. Remember that this is relative to
// the application path defined in `pom.xml`
public class MyExampleServlet {

    String pathPolicyR_offer = "./src/data/policies/PolicyR_offer.trig";
    String pathSHACL_vp = "./src/data/shapes/SHACL_vp.ttl";
    String pathVP = "./src/data/credentials/VP.trig";
    String pathGRAPH_test = "./src/data/credentials/GRAPH_test.ttl";
    String pathSHACL_test = "./src/data/shapes/SHACL_test.ttl";
    String pathSHACL_VP_TTL_Policies = "./src/data/shapes/SHACL_vp_TTL_policies.ttl";
    String pathAgreements = "./src/data/policies/Policy_agreements.trig";

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource(@HeaderParam("authn-data") String authString) {

        // System.out.println(authString);

        String pathSHACL = pathSHACL_test;

        if (authString == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("HTTP ERROR 401 Unauthorized - Provide Credential matching Shape defined in www-authenticate.")
                    .header("WWW-Authenticate",
                            readFile(pathSHACL_VP_TTL_Policies))
                    .header("Content-Type", "text/html")
                    .build();
        }

        if (validateShape(pathSHACL, authString)) {
            if (validateSignature("Resources", "Signature Value")) {
                return Response.ok("Succesfull Authorization: " + authString)
                        .entity("HTTP OK 200 Authorized - Credential matches Shape.")
                        .header("authn-data",
                                readFile(pathAgreements))
                        .header("Content-Type", "text/html")
                        .build();
            }
        }

        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Provide matching Verifiable Presentation.")
                .header("WWW-Authenticate",
                        readFile(pathSHACL_VP_TTL_Policies))
                .header("Content-Type", "text/html")
                .build();

    }

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
        return content;
    }

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

    public boolean validateSignature(String resource, String signatureValue) {
        // Dummy method - signatures need to be checked
        return true;
    }

}

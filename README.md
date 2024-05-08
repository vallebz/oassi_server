# Data Usage Agreement Demo Server
This is a Java servlet that provides a RESTful API endpoint at /resource. It validates credentials against a predefined shape using SHACL (Shapes Constraint Language).

## Prerequisites

- Java Development Kit (JDK) installed
- Apache Jena library added to your project dependencies

## Usage

- Clone or download this repository.
- Set up your Java development environment.
- Import the project into your IDE.
- Run the servlet container (e.g., Apache Tomcat).
- Access the API endpoint at http://localhost:{port}/resource.

## Important Note

This server is required in order to use the Data Usage Agreement Demo https://github.com/vallebz/dua-client. Make sure to have this server running before attempting to access the API endpoint.

```sh
mvn jetty:run
```
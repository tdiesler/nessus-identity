FROM eclipse-temurin:21

WORKDIR /nessus-identity

# Copy dependency jars
COPY target/lib ./lib

# Copy the project jar
COPY target/nessus-identity-openapi-issuer-*.jar ./nessus-identity-openapi-issuer.jar

ENTRYPOINT ["java", "-jar", "nessus-identity-openapi-issuer.jar"]

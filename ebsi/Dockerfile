FROM eclipse-temurin:21

WORKDIR /nessus-identity

# Copy dependency jars
COPY target/lib ./lib

# Copy the project jar
COPY target/nessus-identity-ebsi-portal-*.jar ./nessus-identity-ebsi-portal.jar

ENTRYPOINT ["java", "-jar", "nessus-identity-ebsi-portal.jar"]

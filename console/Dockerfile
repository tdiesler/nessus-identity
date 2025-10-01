FROM eclipse-temurin:21

WORKDIR /nessus-identity

# Copy dependency jars
COPY target/lib ./lib

# Copy the project jar
COPY target/nessus-identity-console-*.jar ./nessus-identity-console.jar

ENTRYPOINT ["java", "-jar", "nessus-identity-console.jar"]

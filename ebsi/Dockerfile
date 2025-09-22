FROM eclipse-temurin:21

ARG PROJECT_VERSION

COPY ./target/nessus-identity-ebsi-portal-*.jar /ebsi/nessus-identity-ebsi-portal.jar

WORKDIR /ebsi

ENTRYPOINT ["java", "-jar", "nessus-identity-ebsi-portal.jar"]

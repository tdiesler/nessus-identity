FROM eclipse-temurin:21

ARG PROJECT_VERSION

COPY ./target/nessus-identity-portal-*.jar /ebsi/nessus-identity-portal.jar

WORKDIR /ebsi

ENTRYPOINT ["java", "-jar", "nessus-identity-portal.jar"]

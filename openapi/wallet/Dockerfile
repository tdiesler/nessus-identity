FROM eclipse-temurin:21

WORKDIR /nessus-identity

# Copy dependency jars
COPY target/lib ./lib

# Pre install Playwright
RUN java -cp "lib/*" com.microsoft.playwright.CLI install-deps
RUN java -cp "lib/*" com.microsoft.playwright.CLI install firefox
RUN java -cp "lib/*" com.microsoft.playwright.CLI install ffmpeg

# Copy the project jar
COPY target/nessus-identity-openapi-wallet-*.jar ./nessus-identity-openapi-wallet.jar

ENTRYPOINT ["java", "-jar", "nessus-identity-openapi-wallet.jar"]

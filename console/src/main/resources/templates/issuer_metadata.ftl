<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>Keycloak Issuer Metadata</h1>
        <p>Issuer Metadata URL: <a href="${issuerMetadataUrl}" target="_blank">${issuerMetadataUrl}</a></p>
        <textarea readonly>${issuerMetadataJson?html}</textarea>

        <h1 style="margin-top: 1rem">EBSI Issuer Metadata</h1>
        <p>Issuer Metadata URL: <a href="${ebsiIssuerMetadataUrl}" target="_blank">${ebsiIssuerMetadataUrl}</a></p>
        <textarea readonly>${ebsiIssuerMetadataJson?html}</textarea>
    </div>
</@layout.layout>

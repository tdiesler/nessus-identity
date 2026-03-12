<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>Keycloak Authorization Metadata</h1>
        <p>Authorization Metadata URL: <a href="${authConfigUrl}" target="_blank">${authConfigUrl}</a></p>
        <textarea readonly>${authConfigJson?html}</textarea>
    </div>
</@layout.layout>

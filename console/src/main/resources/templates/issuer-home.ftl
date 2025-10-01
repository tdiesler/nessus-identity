<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Issuer</h1>
        <p><a href="${issuerUrl}" target="_blank">Keycloak</a></p>
        <p><a href="${issuerConfigUrl}" target="_blank">Issuer Config</a></p>
        <p><a href="${authConfigUrl}" target="_blank">Authorization Config</a></p>
    </div>
</@layout.layout>

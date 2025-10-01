<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <p>Issuer Config URL: <a href="${issuerConfigUrl}" target="_blank">${issuerConfigUrl}</a></p>
        <textarea readonly>${issuerConfigJson?html}</textarea>
    </div>
</@layout.layout>

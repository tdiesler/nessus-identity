<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="ebsi">
    <!-- Sidebar -->
    <#include "fragments/ebsi_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>EBSI Issuer Metadata</h1>
        <p>Issuer Metadata URL: <a href="${issuerMetadataUrl}" target="_blank">${issuerMetadataUrl}</a></p>
        <textarea readonly>${issuerMetadataJson?html}</textarea>
    </div>
</@layout.layout>

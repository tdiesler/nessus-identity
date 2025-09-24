<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <p>Issuer Config URL: <a href="${issuerConfigUrl}">${issuerConfigUrl}</a></p>
        <ul style="margin-top:10px">
            <#list credentialConfigurationIds as id>
                <li style="margin-bottom:6px;">- <a href="/issuer/credential-offer?ctype=${id}">${id}</a></li>
            </#list>
        </ul>
    </div>
</@layout.layout>

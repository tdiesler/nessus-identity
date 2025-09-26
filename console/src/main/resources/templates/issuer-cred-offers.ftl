<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <h5>Credential Configurations</h5>
        <ul class="bx--list--unordered">
            <#list credentialConfigurationIds as id>
                <li class="bx--list__item">
                    ${id} <a href="/issuer/credential-offer?ctype=${id}">offer</a>
                </li>
            </#list>
        </ul>
    </div>
</@layout.layout>

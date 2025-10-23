<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <h5>Credential Configuration for ${ctype}</h5>
        <textarea readonly>${credConfigJson?html}</textarea>
        <div>
            <a href="/issuer/credential-offer?ctype=${ctype}">send offer</a>
        </div>
    </div>
</@layout.layout>

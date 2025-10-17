<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <h5>Credential Configuration for ${ctype}</h5>
        <textarea readonly>${credConfigJson?html}</textarea>
    </div>
</@layout.layout>

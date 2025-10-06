<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Issuer</h1>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                This is the Issuer's main content area.
            </p>
            <p>
                On the left we see links to Keycloak itself and to its respected well-known metadata
                for OIDC and OIDC4VCI.
            </p>
            <p>
                We can then access the list of supported credential configurations that the Issuer can offer to registered Users.
            </p>
        </div>
    </div>
</@layout.layout>

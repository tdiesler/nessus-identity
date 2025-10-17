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
                On the left we have links to
                <a href="https://www.keycloak.org/docs/latest/server_admin/index.html#_oid4vci" target="_blank">Keycloak</a>
                and to its respected well-known metadata for OIDC and OID4VCI.
            </p>
            <p>
                The Issuer can make Credentials Offers from the list of Credential Configurations Supported to registered Users.
            </p>
            <p>
                In future versions of this Console we will be able to manage Credential Configurations and onboard new Users with respective
                properties that can then find their way into issued Credentials.
            </p>
            <p>
                Issuer functionality is defined by
                <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html" target="_blank">OpenID for Verifiable Credential Issuance</a>.
            </p>
        </div>
    </div>
</@layout.layout>

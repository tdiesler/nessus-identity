<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <h5>Credential Configurations</h5>

        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Configurations</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list credentialConfigurationIds as id>
                    <tr>
                        <td>${id}</td>
                        <td>
                            <a href="/issuer/credential-offer?ctype=${id}">send offer</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>
    </div>
</@layout.layout>

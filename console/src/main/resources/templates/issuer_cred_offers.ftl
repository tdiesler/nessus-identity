<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <h3>Credential Configurations</h3>

        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Configurations</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list configIds as cid>
                    <tr>
                        <td>${cid}</td>
                        <td>
                            <a href="/issuer/credential-config/${cid}">view</a>
                            <a href="/issuer/credential-offer/create?configId=${cid}">create</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>
    </div>
</@layout.layout>

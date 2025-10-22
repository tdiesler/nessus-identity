<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <h5>Credential Users</h5>

        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Name</th><th>Email</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list credentialUsers as usr>
                    <tr>
                        <td>${usr.name}</td>
                        <td>${usr.email}</td>
                        <td>
                            <a href="/issuer/user-delete/${usr.id}">delete</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>

        <div style="margin-top: 10px;">
            <a href="/issuer/user-create">create user</a>
        <div>
    </div>
</@layout.layout>

<#macro layout activeTab>
    <!doctype html>
    <html lang="en">
        <#include "fragments/head.ftl">
        <body class="app-body">

            <!-- Role tabs row (Issuer | Wallet | Verifier) -->
            <div class="role-tabs">
                <a href="/issuer" class="<#if activeTab == 'issuer'>active</#if>">Issuer</a>
                <a href="/wallet" class="<#if activeTab == 'wallet'>active</#if>">Wallet</a>
                <a href="/verifier" class="<#if activeTab == 'verifier'>active</#if>">Verifier</a>
            </div>

            <!-- Sub-app content (sidebar + page) -->
            <main class="app-main">
                <#nested>
            </main>

        </body>
    </html>
</#macro>

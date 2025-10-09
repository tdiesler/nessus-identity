<#macro layout activeTab>
    <!doctype html>
    <html lang="en">
        <#include "fragments/head.ftl">
        <body class="app-body">

            <!-- Role tabs row (Issuer | Wallet | Verifier) -->
            <header class="app-header">
                <a href="/issuer" class="<#if activeTab == 'issuer'>active</#if>">Issuer</a>
                <a href="/wallet" class="<#if activeTab == 'wallet'>active</#if>">Wallet</a>
                <a href="/verifier" class="<#if activeTab == 'verifier'>active</#if>">Verifier</a>
            </header>

            <!-- Sub-app content (sidebar + page) -->
            <main class="app-main">
                <#nested>
            </main>

            <footer class="app-footer">
                &copy; 2025 Nessus Identity - ${versionInfo.version}
                <#if versionInfo.revision??>(Rev: ${versionInfo.revision})</#if>
            </footer>
        </body>
    </html>
</#macro>

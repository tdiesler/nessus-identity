<div class="sidebar">
    <ul class="menu-items">
        <li class="bx--list__item"><a href="${issuerUrl}" target="_blank">Keycloak</a></li>
        <li class="bx--list__item"><a href="/issuer/auth-config">Auth Config</a></li>
        <li class="bx--list__item"><a href="/issuer/issuer-config">Issuer Config</a></li>
        <#if holderAuth.hasAuthToken>
            <li class="bx--list__item"><a href="/issuer/credential-offers">Credential Offers</a></li>
        <#else>
            <li class="bx--list__item"><a href="/issuer/credential-offers" class="inactive">Credential Offers</a></li>
        </#if>
        <li class="bx--list__item"><a href="/issuer/users">Users</a></li>
    </ul>
</div>

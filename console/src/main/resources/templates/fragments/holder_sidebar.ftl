<div class="sidebar">
    <ul class="menu-items">
        <#if holderAuth.hasAuthToken>
            <li class="bx--list__item">
                <a class="inactive">Login</a>
                <a href="/wallet/logout">Logout</a>
            </li>
            <li class="bx--list__item"><a href="/wallet/${targetId}/keys" class="inactive">Keys</a></li>
            <li class="bx--list__item"><a href="/wallet/${targetId}/dids" class="inactive">DIDs</a></li>
            <li class="bx--list__item"><a href="/wallet/${targetId}/credential-offers">Credential Offers</a></li>
            <li class="bx--list__item"><a href="/wallet/${targetId}/credentials">Credentials</a></li>
        <#else>
            <li class="bx--list__item">
                <a href="/wallet/login">Login</a>
                <a class="inactive">Logout</a>
            </li>
            <li class="bx--list__item"><a class="inactive">Keys</a></li>
            <li class="bx--list__item"><a class="inactive">DIDs</a></li>
            <li class="bx--list__item"><a class="inactive">Credential Offers</a></li>
            <li class="bx--list__item"><a class="inactive">Credentials</a></li>
        </#if>
    </ul>
</div>

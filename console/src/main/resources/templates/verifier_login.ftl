<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Verifier</h1>

        <form action="/verifier/login" method="post" style="max-width:640px;">
            <!-- Email -->
            <div class="bx--form-item-horizontal">
                <label for="email" class="bx--label">Email</label>
                <input name="email" id="email" class="bx--input" value="bob@email.com" required/>
            </div>
            <!-- Password -->
            <div class="bx--form-item-horizontal">
                <label for="password" class="bx--label">Password</label>
                <input name="password" id="password" class="bx--input" value="password" required/>
            </div>
            <!-- Submit button -->
            <div class="bx--form-item-horizontal">
                <div></div>
                <button type="submit" class="bx--btn bx--btn--primary"
                style="width:auto; padding:0.5rem 1rem; justify-self:start;">
                    Login
                </button>
            </div>
        </form>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                Authenticate the Verifier.
            </p>
        </div>
    </div>
</@layout.layout>

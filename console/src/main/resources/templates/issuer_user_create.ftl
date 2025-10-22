<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <h5>Credential User Create</h5>

        <form action="/issuer/user-create" method="post" style="max-width:640px;">
            <!-- Name -->
            <div class="bx--form-item-horizontal">
                <label for="name" class="bx--label">FirstName</label>
                <input name="name" id="name" class="bx--input" value="Alice Wonderland" required/>
            </div>
            <!-- Email -->
            <div class="bx--form-item-horizontal">
                <label for="email" class="bx--label">Email</label>
                <input name="email" id="email" class="bx--input" value="alice@email.com" required/>
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
                    Create
                </button>
            </div>
        </form>
    </div>
</@layout.layout>

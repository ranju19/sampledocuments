This XML file does not appear to have any style information associated with it. The document tree is shown below.
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="_d3fa7482-fd0a-4aaf-97ee-ff853d7979df" entityID="https://sts.windows.net/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/">
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#_d3fa7482-fd0a-4aaf-97ee-ff853d7979df">
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<DigestValue>M4wlIo5jAumk3bUy+OfYUpdXCAeCV6nh6zlQckkWZFc=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>CXPv52WR/wqpiTmjv1K8J2b+s3vUkGwMwpukrgGAMxtYAoH0Z2eYrb6gT9JbQyVUHQfilzoCvf5utgc/1S/1VY369NvXg0l3dvYZLMYzpjw/E8IN9kGPgC9G3m3M6RSibfeIb3atKEnelFiE+Fe4Es2p1Jlj56U6ulYpPB8tmZVACnveAeRtfZDKZJPry+HOTis1Bx6aVz8CCPAMX6ZwOFeA+K2fhpv2KCvPntUFHHc8bItst20cu+KGx7h0SLqBquGHnTlrL9GQfpJukTXiCMMt2IgWIISyH543I37H1OrK0euOcYcsmHQrT1AA+kf9JUFnc/CRv1RvAZttt3Hijw==</SignatureValue>
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0yODA3MjkxNzU2MTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueiSa6qmEWWbabDFoGj7eA1JulBGbKiRPbHtloSfGSqUvY8kLIehrVmtScD0Bc+/Pf5cWsYaOYQa4X37QvRETGlOOOpJHCmHwgAZRbs/jEMCk5Cxt279I3G27682XVojIstwbwTJjHObpZR79ez2LyFuHWvcXe42fRqKbCDclEW9mNdAM2DymZYSI6tlDpVUmIoiMKk7KB5/RpDoBEXhl2ksYW4GidqULFCri98IxAAlwrdO8n7HVbuqmXj7qPLT1qrbYDum440PrVL/+grSXJBo2rOYikdWgdx/ymfKhvrTXVM8JiW6Zm7Z0eYdadF37Y3KTxwU95fP21hbz2hF1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA1puJa9iV0f57r3ILLcfqIoDY2NtT9R8m/VDyudyBSW3Eb99V9Z67Xy7Z2kX/7GLIA3y0Ykln57CzoWK7Dl49fhcSkSLmedy6pdoHzhEkZ5SLw1PQARQxUKwhJSoaCiwv5sk0A+WzvDsbGWHUB//Ljmjy4cvkayc2tpv0iCm1Aeq1A/hHIxVjtNBH3dMS4q3QjLfk+5bhzJbhuSAWm+ai6PXryiEzavDd8KcNVX9DZZAlgiWGvPMUWTSe5xE7Kl7ALn20MTVVJC9/yKu+sVKcqkXQIuA+nMaNyzbiXXnWomRm1XSy3USzGdOHnzOvOlW62erBd8ArKkfj44AaKQFFs</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</Signature>
<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0yODA3MjkxNzU2MTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueiSa6qmEWWbabDFoGj7eA1JulBGbKiRPbHtloSfGSqUvY8kLIehrVmtScD0Bc+/Pf5cWsYaOYQa4X37QvRETGlOOOpJHCmHwgAZRbs/jEMCk5Cxt279I3G27682XVojIstwbwTJjHObpZR79ez2LyFuHWvcXe42fRqKbCDclEW9mNdAM2DymZYSI6tlDpVUmIoiMKk7KB5/RpDoBEXhl2ksYW4GidqULFCri98IxAAlwrdO8n7HVbuqmXj7qPLT1qrbYDum440PrVL/+grSXJBo2rOYikdWgdx/ymfKhvrTXVM8JiW6Zm7Z0eYdadF37Y3KTxwU95fP21hbz2hF1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA1puJa9iV0f57r3ILLcfqIoDY2NtT9R8m/VDyudyBSW3Eb99V9Z67Xy7Z2kX/7GLIA3y0Ykln57CzoWK7Dl49fhcSkSLmedy6pdoHzhEkZ5SLw1PQARQxUKwhJSoaCiwv5sk0A+WzvDsbGWHUB//Ljmjy4cvkayc2tpv0iCm1Aeq1A/hHIxVjtNBH3dMS4q3QjLfk+5bhzJbhuSAWm+ai6PXryiEzavDd8KcNVX9DZZAlgiWGvPMUWTSe5xE7Kl7ALn20MTVVJC9/yKu+sVKcqkXQIuA+nMaNyzbiXXnWomRm1XSy3USzGdOHnzOvOlW62erBd8ArKkfj44AaKQFFs</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<fed:ClaimTypesOffered>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
<auth:DisplayName>Name</auth:DisplayName>
<auth:Description>The mutable display name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier">
<auth:DisplayName>Subject</auth:DisplayName>
<auth:Description>An immutable, globally unique, non-reusable identifier of the user that is unique to the application for which a token is issued.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
<auth:DisplayName>Given Name</auth:DisplayName>
<auth:Description>First name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
<auth:DisplayName>Surname</auth:DisplayName>
<auth:Description>Last name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/displayname">
<auth:DisplayName>Display Name</auth:DisplayName>
<auth:Description>Display name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/nickname">
<auth:DisplayName>Nick Name</auth:DisplayName>
<auth:Description>Nick name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant">
<auth:DisplayName>Authentication Instant</auth:DisplayName>
<auth:Description>The time (UTC) when the user is authenticated to Windows Azure Active Directory.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod">
<auth:DisplayName>Authentication Method</auth:DisplayName>
<auth:Description>The method that Windows Azure Active Directory uses to authenticate users.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/objectidentifier">
<auth:DisplayName>ObjectIdentifier</auth:DisplayName>
<auth:Description>Primary identifier for the user in the directory. Immutable, globally unique, non-reusable.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/tenantid">
<auth:DisplayName>TenantId</auth:DisplayName>
<auth:Description>Identifier for the user's tenant.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/identityprovider">
<auth:DisplayName>IdentityProvider</auth:DisplayName>
<auth:Description>Identity provider for the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
<auth:DisplayName>Email</auth:DisplayName>
<auth:Description>Email address of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">
<auth:DisplayName>Groups</auth:DisplayName>
<auth:Description>Groups of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/accesstoken">
<auth:DisplayName>External Access Token</auth:DisplayName>
<auth:Description>Access token issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration">
<auth:DisplayName>External Access Token Expiration</auth:DisplayName>
<auth:Description>UTC expiration time of access token issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/openid2_id">
<auth:DisplayName>External OpenID 2.0 Identifier</auth:DisplayName>
<auth:Description>OpenID 2.0 identifier issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/claims/groups.link">
<auth:DisplayName>GroupsOverageClaim</auth:DisplayName>
<auth:Description>Issued when number of user's group claims exceeds return limit.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
<auth:DisplayName>Role Claim</auth:DisplayName>
<auth:Description>Roles that the user or Service Principal is attached to</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/wids">
<auth:DisplayName>RoleTemplate Id Claim</auth:DisplayName>
<auth:Description>Role template id of the Built-in Directory Roles that the user is a member of</auth:Description>
</auth:ClaimType>
</fed:ClaimTypesOffered>
<fed:SecurityTokenServiceEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:SecurityTokenServiceEndpoint>
<fed:PassiveRequestorEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:PassiveRequestorEndpoint>
</RoleDescriptor>
<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0yODA3MjkxNzU2MTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueiSa6qmEWWbabDFoGj7eA1JulBGbKiRPbHtloSfGSqUvY8kLIehrVmtScD0Bc+/Pf5cWsYaOYQa4X37QvRETGlOOOpJHCmHwgAZRbs/jEMCk5Cxt279I3G27682XVojIstwbwTJjHObpZR79ez2LyFuHWvcXe42fRqKbCDclEW9mNdAM2DymZYSI6tlDpVUmIoiMKk7KB5/RpDoBEXhl2ksYW4GidqULFCri98IxAAlwrdO8n7HVbuqmXj7qPLT1qrbYDum440PrVL/+grSXJBo2rOYikdWgdx/ymfKhvrTXVM8JiW6Zm7Z0eYdadF37Y3KTxwU95fP21hbz2hF1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA1puJa9iV0f57r3ILLcfqIoDY2NtT9R8m/VDyudyBSW3Eb99V9Z67Xy7Z2kX/7GLIA3y0Ykln57CzoWK7Dl49fhcSkSLmedy6pdoHzhEkZ5SLw1PQARQxUKwhJSoaCiwv5sk0A+WzvDsbGWHUB//Ljmjy4cvkayc2tpv0iCm1Aeq1A/hHIxVjtNBH3dMS4q3QjLfk+5bhzJbhuSAWm+ai6PXryiEzavDd8KcNVX9DZZAlgiWGvPMUWTSe5xE7Kl7ALn20MTVVJC9/yKu+sVKcqkXQIuA+nMaNyzbiXXnWomRm1XSy3USzGdOHnzOvOlW62erBd8ArKkfj44AaKQFFs</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<fed:TargetScopes>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://sts.windows.net/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/</wsa:Address>
</wsa:EndpointReference>
</fed:TargetScopes>
<fed:ApplicationServiceEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:ApplicationServiceEndpoint>
<fed:PassiveRequestorEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:PassiveRequestorEndpoint>
</RoleDescriptor>
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0yODA3MjkxNzU2MTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueiSa6qmEWWbabDFoGj7eA1JulBGbKiRPbHtloSfGSqUvY8kLIehrVmtScD0Bc+/Pf5cWsYaOYQa4X37QvRETGlOOOpJHCmHwgAZRbs/jEMCk5Cxt279I3G27682XVojIstwbwTJjHObpZR79ez2LyFuHWvcXe42fRqKbCDclEW9mNdAM2DymZYSI6tlDpVUmIoiMKk7KB5/RpDoBEXhl2ksYW4GidqULFCri98IxAAlwrdO8n7HVbuqmXj7qPLT1qrbYDum440PrVL/+grSXJBo2rOYikdWgdx/ymfKhvrTXVM8JiW6Zm7Z0eYdadF37Y3KTxwU95fP21hbz2hF1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA1puJa9iV0f57r3ILLcfqIoDY2NtT9R8m/VDyudyBSW3Eb99V9Z67Xy7Z2kX/7GLIA3y0Ykln57CzoWK7Dl49fhcSkSLmedy6pdoHzhEkZ5SLw1PQARQxUKwhJSoaCiwv5sk0A+WzvDsbGWHUB//Ljmjy4cvkayc2tpv0iCm1Aeq1A/hHIxVjtNBH3dMS4q3QjLfk+5bhzJbhuSAWm+ai6PXryiEzavDd8KcNVX9DZZAlgiWGvPMUWTSe5xE7Kl7ALn20MTVVJC9/yKu+sVKcqkXQIuA+nMaNyzbiXXnWomRm1XSy3USzGdOHnzOvOlW62erBd8ArKkfj44AaKQFFs</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2"/>
</IDPSSODescriptor>
</EntityDescriptor>


Settings.json
{
  "strict": true,
  "debug": true,
  "sp": {
    "entityId": "http://localhost:5000/metadata/",
    "assertionConsumerService": {
      "url": "http://localhost:5000/saml/acs/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "singleLogoutService": {
      "url": "http://localhost:5000/saml/sls/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "",
    "privateKey": ""
  },
  "idp": {
    "entityId": "https://sts.windows.net/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/",
    "singleSignOnService": {
      "url": "https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "<X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNT>
  }
}








---------------------------------------------------------------------------------------------
sudo ln -s /etc/nginx/sites-available/flaskapp /etc/nginx/sites-enabled/

sudo rm /etc/nginx/sites-enabled/default


server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}



curl -X POST -H "Content-Type: application/json" -d '{"message":"Hello"}' http://127.0.0.1:8000/api/threads


@app.route('/api/threads', methods=['GET', 'POST'])
def threads_api():
    if request.method == 'GET':
        return jsonify(threads)
    elif request.method == 'POST':
        data = request.json
        # Simple validation (adjust as needed)
        if not data or 'message' not in data:
            return jsonify({"error": "No message provided"}), 400
        threads.append({"message": data['message']})
        return jsonify({"status": "ok"}), 201



@app.route('/api/threads', methods=['GET'])
def get_threads():
    # Sample threads. Replace this with your DB logic if needed.
    threads = [
        {"id": 1, "title": "Welcome!", "user": "admin"},
        {"id": 2, "title": "First Chatroom Thread", "user": "ranju"},
    ]
    return jsonify(threads), 200



1
Directly BELOW it, add:
from flask import session, redirect, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

2
def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))

3
@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f"SAML error: {errors}"
    session['samlUserdata'] = auth.get_attributes()
    return redirect(url_for('protected'))

@app.route('/protected')
def protected():
    if 'samlUserdata' in session:
        return jsonify({"SSO_user": session['samlUserdata']})
    return redirect(url_for('saml_login'))

4
app.secret_key = 'some-super-secret-key'  # use a strong, random value for production!






from flask import Flask, request, jsonify
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({"error": "Missing fields"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User exists"}), 400
    user = User(username=data['username'], password=data['password'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Signup successful!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username'], password=data['password']).first()
    if user:
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/search', methods=['GET'])
def search():
    q = request.args.get('q', '')
    results = User.query.filter(User.username.ilike(f'%{q}%')).all()
    return jsonify([{"username": u.username, "email": u.email} for u in results])

@app.route('/ping',methods=['GET'])
def ping():
    return "pong", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)


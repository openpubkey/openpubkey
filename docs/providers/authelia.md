# Authelia Integration

Tested with Authelia v4.39.10

## OAuth 2.0 Device Authorization Grant (DeviceFlow)

```
...
    identity_providers:
      oidc:
        enabled: true
        claims_policies:
          opkssh:
            id_token:
              - email
              - groups
        clients:
          - client_id: 'opkssh'
            client_name: 'opkssh'
            public: true
            authorization_policy: 'one_factor'
            require_pkce: true
            pkce_challenge_method: 'S256'
            scopes:
              - 'openid'
              - 'groups'
              - 'email'
              - 'profile'
            response_types:
              - 'code'
            grant_types:
              - 'urn:ietf:params:oauth:grant-type:device_code'
            access_token_signed_response_alg: 'none'
            device_authorization_endpoint_auth_method: 'none'
            userinfo_signed_response_alg: 'none'
            token_endpoint_auth_method: 'none'
            claims_policy: opkssh
...
```

* - This setup adds the `emai`l and `groups` token directly into the id-token. 
    It should be possible only add the `email` and `groups` to the userinfo endpoint.

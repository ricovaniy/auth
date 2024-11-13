// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using System.Collections.Generic;
using IdentityServer4;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            { 
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource("photos_app", "Web Photos", new []
                {
                    "role", "subscription", "testing"
                })
            };

        public static IEnumerable<ApiResource> Apis =>
            new ApiResource[] 
            {
                new ApiResource("photos_service", "Сервис фотографий")
                {
                    Scopes = { "photos"},
                    ApiSecrets = { new Secret("photos_service_secret".Sha256()) }
                }
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("photos", "Фотографии"),
            };
        
        public static IEnumerable<Client> Clients =>
            new Client[] 
            {
                new Client
                {
                    ClientId = "Photos App by OAuth",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = { "photos" },
                },
                new Client
                {
                    ClientId = "Photos App by OIDC",
                    AccessTokenLifetime = 30,
                    AllowOfflineAccess = true,
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    
                    RequireConsent = true,
                    
                    RedirectUris = { "https://localhost:5001/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:5001/signout-callback-passport" },
                    
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "photos_app",
                        "photos"
                    },
                    AlwaysIncludeUserClaimsInIdToken = true,
                },
                new Client
                {
                    ClientId = "Photos SPA",
                    RequireClientSecret = false,
                    RequirePkce = true,

                    AllowedGrantTypes = GrantTypes.Code,
                    
                    RequireConsent = false,
                    
                    RedirectUris = { "https://localhost:8001/authentication/signin-passport" },
                    
                    PostLogoutRedirectUris = { "https://localhost:8001/authentication/signout-passport" },
                    
                    AllowedCorsOrigins = { "https://localhost:8001" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "photos"
                    },
                    
                    AlwaysIncludeUserClaimsInIdToken = true,
                    
                    AllowOfflineAccess = false,
                    
                    AccessTokenLifetime = 2*60,
                }
            };
    }
}
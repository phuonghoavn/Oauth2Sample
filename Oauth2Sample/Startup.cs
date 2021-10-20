using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Oauth2Sample.Providers;
using Owin;
using System;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(Oauth2Sample.Startup))]

namespace Oauth2Sample
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            var oAuthOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true, // need set to false in PROD
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(60), //token expiration time
                Provider = new OAuthProvider(),
            };

            app.UseOAuthBearerAuthentication(OAuthBearerOptions);
            app.UseOAuthAuthorizationServer(oAuthOptions);
        }
    }
}

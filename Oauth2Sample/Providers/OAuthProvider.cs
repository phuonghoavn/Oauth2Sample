using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Oauth2Sample.Providers
{
    public class OAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly string sampleClientId = "9bd361d7-2750-4423-92d4-9a6bee6dd7ae";
        private readonly string sampleSecretId = "client_secret";
        private readonly int sampleMaxConnection = 20;

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            Guid clientIdGuid;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (null == context.ClientId || null == clientSecret || !Guid.TryParse(clientId, out clientIdGuid))
            {
                context.SetError("invalid_credentials", "A valid client_Id and client_Secret must be provided.");
                context.Rejected();
                return;
            }

            bool isValidClient = sampleClientId == clientId && sampleSecretId == clientSecret;
            if (!isValidClient)
            {
                context.SetError("invalid_credentials", "A valid client_Id and client_Secret must be provided.");
                context.Rejected();
                return;
            }

            //valid number connected
            var totalClientConnect = getNumberConnected();

            if (totalClientConnect > sampleMaxConnection)
            {
                context.SetError("max_connection", "Client group has greater 20");
                return;
            }

            await Task.Run(() => context.Validated(clientId));
        }

        private int getNumberConnected()
        {
            Random r = new Random();

            return r.Next(0, sampleMaxConnection * 2);
        }

        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            Guid clientId;
            Guid.TryParse(context.ClientId, out clientId);
            bool client = sampleClientId == clientId.ToString();
            if (!client)
            {
                context.SetError("invalid_grant", "Invaild client.");
                context.Rejected();
                return;
            }

            var claimsIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            claimsIdentity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));

            await Task.Run(() => context.Validated(claimsIdentity));
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            if (context.TokenIssued)
            {
                context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(3600);
            }

            return Task.FromResult<object>(null);
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace WebApplication1.AuthFilters
{
    public class CustomAuthFilter : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }

        public CustomAuthFilter()
        {
            Console.WriteLine ("CustomAuthFilter constructor");
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;
            if (req.Headers.Authorization != null &&
                    req.Headers.Authorization.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase))
            {
                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string credentials = encoding.GetString(Convert.FromBase64String(req.Headers.Authorization.Parameter));
                string[] parts = credentials.Split(':');
                string userId = parts[0].Trim();
                string password = parts[1].Trim();

                if (userId.Equals("sukata")) 
                {
                    var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, "claim")
                };
                    var id = new ClaimsIdentity(claims, "Basic");
                    var principal = new ClaimsPrincipal(new[] { id });
                    context.Principal = principal;
                }
            }
            else if (context.Principal != null && context.Principal.GetType() == typeof(WindowsPrincipal))
            {
                // Do nothing because it is a windows AD user
            }
            
            if (context.Principal == null)
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(context);
        }

        public async Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            //if (context.Request)
            //IPrincipal incomingPrincipal = context.ActionContext.RequestContext.Principal;
            //if (incomingPrincipal == null)
            //{
            //    var challenge = new AuthenticationHeaderValue("Basic");
            //    context.Result = new AddChallengeOnUnauthorizedResult(challenge, context.Result);
            //}
            //else
            //{

            //}
            //return Task.FromResult(0);
            await Task.Run(() =>
            {
                if (context.ActionContext.RequestContext.Principal == null)
                {
                    var challenge = new AuthenticationHeaderValue("Basic");
                    context.Result = new AddChallengeOnUnauthorizedResult(challenge, context.Result);
                }
                else
                {
                    IPrincipal incomingPrincipal = context.ActionContext.RequestContext.Principal;
                    Console.WriteLine(String.Format("Incoming principal in custom auth filter ChallengeAsync method is authenticated: {0}", incomingPrincipal.Identity.IsAuthenticated));
                }
            });
        }
    }
}
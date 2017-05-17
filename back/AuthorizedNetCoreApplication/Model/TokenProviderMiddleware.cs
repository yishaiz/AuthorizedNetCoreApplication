using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http.Internal;
using System.IO;

namespace AuthorizedNetCoreApplication.Model
{
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TokenProviderOptions _options;

        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options)
        {
            _next = next;
            _options = options.Value;
        }

        public Task Invoke(HttpContext context)
        {
            // If the request path doesn't match, skip
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                return _next(context);
            }

            // Request must be POST //                      with Content-Type: application/x-www-form-urlencoded
            if (!context.Request.Method.Equals("POST")) //  || !context.Request.HasFormContentType
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Bad request.");
            }

            LoginUser user = GetLoginUserFromJson(context);

            if (user == null)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Invalid username or password.");
            }

            bool isAuthenticatedUser =  IsAuthenticatedUser(user);
            //bool isAuthenticatedUser = await IsAuthenticatedUser(user);


            if (!isAuthenticatedUser)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Invalid username or password.");
            }

            //authenticated :)

            return GenerateToken(context);
        }


        private LoginUser GetLoginUserFromJson(HttpContext context)
        {
            LoginUser user = null;

            try
            {
                string jsonData = GetRequestJson(context);

                user = JsonConvert.DeserializeObject<LoginUser>(jsonData);
            }
            catch (Exception ex)
            {
                //can log or do something...
                //throw;
            }

            return user;
        }

        private string GetRequestJson(HttpContext context)
        {
            //context.Request.EnableRewind();

            return new StreamReader(context.Request.Body).ReadToEnd();
        }


        //private Task<ClaimsIdentity> GetIdentity(string username, string password)
        //{
        //    if (username == "TEST" && password == "TEST123")
        //    {
        //        return Task.FromResult(new ClaimsIdentity(new System.Security.Principal.GenericIdentity(username, "Token"), new Claim[] { }));
        //    }

        //    // Credentials are invalid, or account doesn't exist
        //    return Task.FromResult<ClaimsIdentity>(null);
        //}

        private   bool  IsAuthenticatedUser(LoginUser user)
        {
             bool isAuthenticatedUser = IsAuthenticatedUserFromConfig(user);

            return isAuthenticatedUser;
        }



        private  bool  IsAuthenticatedUserFromConfig(LoginUser user)
        {

            //todo: get from config
            return  user.Username == "TEST" && user.Password == "1234" ;
            //return Task.FromResult(user.Username == "TEST" && user.Password == "1234");


            throw new NotImplementedException();
        }

        private async Task GenerateToken(HttpContext context)
        {
            var username = context.Request.Form["username"];
            var password = context.Request.Form["password"];

            var identity = await GetIdentity(username, password);

            if (identity == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid username or password.");
                return;
            }

            var now = DateTime.UtcNow;

            // Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToString(), ClaimValueTypes.Integer64)
            };

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.Expiration),
                signingCredentials: _options.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)_options.Expiration.TotalSeconds
            };

            // Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented }));
        }

        private Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            if (username == "TEST" && password == "TEST123")
            {
                return Task.FromResult(new ClaimsIdentity(new System.Security.Principal.GenericIdentity(username, "Token"), new Claim[] { }));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

    }
}

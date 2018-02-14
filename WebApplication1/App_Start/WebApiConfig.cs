using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using WebApplication1.AuthFilters;

namespace WebApplication1
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            //config.SuppressHostPrincipal();

            //config.Filters.Add(new CustomAuthFilter());

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}

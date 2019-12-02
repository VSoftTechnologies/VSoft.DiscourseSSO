using DotNetNuke.Web.Mvc.Routing;

namespace VSoft.DiscourseSSO
{
	public class RouteConfig : IMvcRouteMapper
	{
		public void RegisterRoutes(IMapRoute mapRouteManager)
		{
			mapRouteManager.MapRoute("VSoft.DiscourseSSO", "VSoft.DiscourseSSO", "{controller}/{action}", new[] { "VSoft.DiscourseSSO.Controllers" });
		}
	}
}
#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class ExternalAPIs
	{
		internal static Dictionary<string, object> APIs = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

		internal static Task ProcessRequestAsync(HttpContext context)
		{
			return Task.CompletedTask;
		}
	}
}
#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class ExternalAPIs
	{
		internal static Dictionary<string, object> APIs = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

		internal static Task ProcessRequestAsync(HttpContext context) => Task.CompletedTask;
	}
}
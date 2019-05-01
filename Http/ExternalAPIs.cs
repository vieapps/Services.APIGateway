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
		public static Dictionary<string, object> APIs { get; } = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

		public static Task ProcessRequestAsync(HttpContext context) => Task.CompletedTask;
	}
}
#region Related components
using System;
using System.Net;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class RequestHandler
	{
		readonly RequestDelegate _next;
		readonly IHostingEnvironment _hostingEnvironment;

		public RequestHandler(RequestDelegate next, IHostingEnvironment hostingEnvironment)
		{
			this._next = next;
			this._hostingEnvironment = hostingEnvironment;
		}

		public async Task InvokeAsync(HttpContext context)
		{
			// request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
				await RTU.WebSocket.WrapAsync(context).ConfigureAwait(false);

			// request with OPTIONS
			else if (context.Request.Method.IsEquals("OPTIONS"))
			{
				context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
				context.Response.Headers.Add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
				if (context.Request.Headers.ContainsKey("Access-Control-Request-Headers"))
					context.Response.Headers.Add("Access-Control-Request-Headers", context.Request.Headers["Access-Control-Request-Headers"]);
			}

			// request with other verbs
			else
				await this.ProcessRequestAsync(context).ConfigureAwait(false);

			// invoke next middleware
			try
			{
				await this._next.Invoke(context).ConfigureAwait(false);
			}
			catch (InvalidOperationException) { }
			catch (Exception ex)
			{
				await context.WriteLogsAsync("RequestHandler", $"Error occurred while invoking the next middleware: {ex.Message}", ex);
			}
		}

		internal async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			var requestUri = context.GetRequestUri();
			var correlationID = context.GetCorrelationID();
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();

			var executionFilePath = requestUri.PathAndQuery;
			if (executionFilePath.IndexOf("?") > 0)
				executionFilePath = executionFilePath.Left(executionFilePath.IndexOf("?"));
			if (executionFilePath.Equals("~/") || executionFilePath.Equals("/"))
				executionFilePath = "";
			var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
				? new[] { "" }
				: executionFilePath.ToLower().ToArray('/', true);

			// request to favicon.ico file
			if (executionFilePaths[0].IsEquals("favicon.ico"))
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

			// request to by-pass segments
			else if (Global.BypassSegments.Count > 0 && Global.BypassSegments.Contains(executionFilePaths[0]))
			{
				// do nothinng
			}

			// request to static segments
			else if (Global.StaticSegments.Count > 0 && Global.StaticSegments.Contains(executionFilePaths[0]))
				try
				{
					await this.ProcessStaticRequestAsync(context, executionFilePaths[0]).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID());
					await context.WriteLogsAsync("StaticFiles", $"Error occurred while processing static file [{requestUri}]", ex);
				}

			// request to external APIs
			else if (ExternalAPIs.APIs.ContainsKey(executionFilePaths[0]))
				await ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			// request to internal APIs
			else
				await InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
		}

		internal async Task ProcessStaticRequestAsync(HttpContext context, string path)
		{
			// check "If-Modified-Since" request to reduce traffic
			var requestUri = context.GetRequestUri();
			var eTag = "Static#" + $"{requestUri}".ToLower().GenerateUUID();
			if (!string.IsNullOrWhiteSpace(context.Request.Headers["If-Modified-Since"]) && eTag.IsEquals(context.Request.Headers["If-None-Match"]))
			{
				context.SetResponseHeaders((int)HttpStatusCode.NotModified, new Dictionary<string, string>
				{
					{ "Cache-Control", "public" },
					{ "ETag", $"\"{eTag}\"" }
				});
				return;
			}

			// prepare
			var rootPath = path.IsEquals("statics")
				? UtilityService.GetAppSetting("Path:StaticFiles", this._hostingEnvironment.ContentRootPath + "/data-files/statics")
				: this._hostingEnvironment.ContentRootPath;

			var filePath = string.IsNullOrWhiteSpace(requestUri.PathAndQuery)
				? "/geo/countries.json"
				: requestUri.PathAndQuery;

			if (filePath.IndexOf("?") > 0)
				filePath = filePath.Left(filePath.IndexOf("?"));

			filePath = (rootPath + filePath.Replace("/statics/", "/")).Replace("//", "/").Replace(@"\", "/").Replace("/", Path.DirectorySeparatorChar.ToString());

			// check existed
			var fileInfo = new FileInfo(filePath);
			if (!fileInfo.Exists)
				throw new FileNotFoundException($"Not Found [{requestUri}]");

			// update headers
			new FileExtensionContentTypeProvider().TryGetContentType(fileInfo.Name, out string staticMimeType);
			context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
			{
				{ "Content-Type", string.IsNullOrWhiteSpace(staticMimeType) ? "text/plain" : staticMimeType },
				{ "ETag", $"\"{eTag}\"" },
				{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
				{ "Cache-Control", "public" },
				{ "Expires", $"{fileInfo.LastWriteTime.AddDays(30).ToHttpString()}" },
			});

			// write body
			var staticContent = await UtilityService.ReadTextFileAsync(fileInfo).ConfigureAwait(false);
			staticContent = staticMimeType.IsEndsWith("json")
				? JObject.Parse(staticContent).ToString(Formatting.Indented)
				: staticContent;

			await Task.WhenAll(
				context.WriteAsync(staticContent.ToBytes()),
				Global.IsDebugLogEnabled ? context.WriteLogsAsync("StaticFiles", $"Process request of static file successful [{filePath}]") : Task.CompletedTask
			).ConfigureAwait(false);
		}
	}
}
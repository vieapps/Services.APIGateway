#region Related components
using System;
using System.Net;
using System.Text;
using System.Web;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;

using net.vieapps.Services.Base.AspNet;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public static partial class Global
	{

		#region Attributes
		internal static IDisposable InterCommunicateMessageUpdater = null;

		static HashSet<string> QueryExcluded = "service-name,object-name,object-identity,request-of-static-resource".ToHashSet();

		static Cache _Cache = new Cache("VIEApps-API-Gateway", 120, UtilityService.GetAppSetting("CacheProvider"));

		public static Cache Cache { get { return Global._Cache; } }
		#endregion

		#region Start/End the app
		internal static HashSet<string> HiddenSegments = null, BypassSegments = null, StaticSegments = null;

		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// default service name
			Base.AspNet.Global.ServiceName = "APIGateway";

			// open WAMP channels
			Task.Run(async () =>
			{
				await Base.AspNet.Global.OpenChannelsAsync(
					(sender, args) =>
					{
						Global.InterCommunicateMessageUpdater = Base.AspNet.Global.IncommingChannel.RealmProxy.Services
							.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
							.Subscribe(
								message => Global.ProcessInterCommunicateMessage(message),
								exception => Base.AspNet.Global.WriteLogs(UtilityService.BlankUID, "RTU", "Error occurred while fetching inter-communicate message", exception)
							);
					},
					(sender, args) =>
					{
						Task.Run(async () =>
						{
							try
							{
								await Base.AspNet.Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
								await Base.AspNet.Global.InitializeRTUServiceAsync().ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								Base.AspNet.Global.WriteLogs("Error occurred while initializing helper services", ex);
							}
						}).ConfigureAwait(false);
					}
				);
			}).ConfigureAwait(false);

			// special segments
			Global.BypassSegments = UtilityService.GetAppSetting("BypassSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.HiddenSegments = UtilityService.GetAppSetting("HiddenSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.StaticSegments = UtilityService.GetAppSetting("StaticSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.StaticSegments.Append("statics");

			// handling unhandled exception
			AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
			{
				Base.AspNet.Global.WriteLogs("An unhandled exception is thrown", args.ExceptionObject as Exception);
			};

			stopwatch.Stop();
			Base.AspNet.Global.WriteLogs($"*** The API Gateway is ready for serving. The app is initialized in {stopwatch.GetElapsedTimes()}");
		}

		internal static void OnAppEnd()
		{
			Base.AspNet.Global.CancellationTokenSource.Cancel();
			Base.AspNet.Global.CancellationTokenSource.Dispose();

			Global.InterCommunicateMessageUpdater?.Dispose();
			RTU.StopUpdaters();

			Base.AspNet.Global.CloseChannels();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.Headers.Add("access-control-allow-origin", "*");
			app.Context.Response.Headers.Add("x-correlation-id", Base.AspNet.Global.GetCorrelationID(app.Context.Items));

			// prepare
			var executionFilePath = app.Request.AppRelativeCurrentExecutionFilePath;
			if (executionFilePath.StartsWith("~/"))
				executionFilePath = executionFilePath.Right(executionFilePath.Length - 2);

			var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
				? new string[] {""}
				: executionFilePath.ToLower().ToArray('/', true);

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.Headers.Add("access-control-allow-methods", "GET,POST,PUT,DELETE");

				var allowHeaders = app.Context.Request.Headers.Get("access-control-request-headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.Headers.Add("access-control-allow-headers", allowHeaders);

				return;
			}

			// by-pass segments
			else if (Global.BypassSegments.Count > 0 && Global.BypassSegments.Contains(executionFilePaths[0]))
				return;

			// hidden segments
			else if (Global.HiddenSegments.Count > 0 && Global.HiddenSegments.Contains(executionFilePaths[0]))
			{
				Global.ShowError(app.Context, 403, "Forbidden", "AccessDeniedException", null, null);
				app.Context.Response.End();
				return;
			}

			// 403/404 errors
			else if (executionFilePaths[0].IsEquals("global.ashx"))
			{
				var errorElements = app.Context.Request.QueryString != null && app.Context.Request.QueryString.Count > 0
					? app.Context.Request.QueryString.ToString().UrlDecode().ToArray(';')
					: new string[] { "500", "" };
				var errorMessage = errorElements[0].Equals("403")
					? "Forbidden"
					: errorElements[0].Equals("404")
						? "Invalid"
						: "Unknown (" + errorElements[0] + " : " + (errorElements.Length > 1 ? errorElements[1].Replace(":80", "").Replace(":443", "") : "unknown") + ")";
				var errorType = errorElements[0].Equals("403")
					? "AccessDeniedException"
					: errorElements[0].Equals("404")
						? "InvalidRequestException"
						: "Unknown";						
				Global.ShowError(app.Context, errorElements[0].CastAs<int>(), errorMessage, errorType, null, null);
				app.Context.Response.End();
				return;
			}

#if DEBUG || REQUESTLOGS
			var appInfo = app.Context.GetAppInfo();
			var logs = new List<string>() {
				$"Begin process [{app.Context.Request.HttpMethod}]: {app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + app.Context.Request.RawUrl}",
				$"- Origin: {appInfo.Item1} / {appInfo.Item2} - {appInfo.Item3}",
				$"- IP: {app.Context.Request.UserHostAddress} [{app.Context.Request.UserAgent}]"
			};

			if (!executionFilePaths[0].IsEquals("rtu"))
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}
#endif

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx";
			if (Global.StaticSegments.Contains(executionFilePaths[0]))
				url += "?request-of-static-resource=&path=" + app.Context.Request.RawUrl.UrlEncode();
			else
			{
				url += "?service-name=" + (!string.IsNullOrWhiteSpace(executionFilePaths[0]) ? executionFilePaths[0].GetANSIUri() : "");
				if (executionFilePaths.Length > 1)
					url += "&object-name=" + executionFilePaths[1].GetANSIUri();
				if (executionFilePaths.Length > 2)
					url += "&object-identity=" + executionFilePaths[2].GetANSIUri();
			}

			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key) && !Global.QueryExcluded.Contains(key))
					url += "&" + key + "=" + app.Request.QueryString[key].UrlEncode();

#if DEBUG || REQUESTLOGS
			logs.Add($"Rewrite URL: [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + app.Context.Request.RawUrl}] ==> [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + url}]");
			Base.AspNet.Global.WriteLogs(logs);
#endif

			app.Context.RewritePath(url);
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
#if DEBUG || REQUESTLOGS
			if (!app.Context.Request.HttpMethod.Equals("OPTIONS") && app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				var executionTimes = (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes();
				Base.AspNet.Global.WriteLogs($"End process - Execution times: {executionTimes}");
				try
				{
					app.Response.Headers.Add("x-execution-times", executionTimes);
				}
				catch { }
			}
#endif
		}
		#endregion

		#region Pre excute handlers/send headers
		internal static void OnAppPreHandlerExecute(HttpApplication app)
		{
			// check
			if (app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Context.Request.Headers["accept-encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
				return;

			// apply compression
			var previousStream = app.Context.Response.Filter;

			// deflate
			if (acceptEncoding.IsContains("deflate") || acceptEncoding.Equals("*"))
			{
				app.Context.Response.Filter = new DeflateStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "deflate");
			}

			// gzip
			else if (acceptEncoding.IsContains("gzip"))
			{
				app.Context.Response.Filter = new GZipStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "gzip");
			}
		}

		internal static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("allow");
			app.Context.Response.Headers.Remove("public");
			app.Context.Response.Headers.Remove("x-powered-by");

			// add special headers
			if (app.Response.Headers["server"] != null)
				app.Response.Headers.Set("server", "VIEApps NGX");
			else
				app.Response.Headers.Add("server", "VIEApps NGX");
		}
		#endregion

		#region Error handlings
		static string ShowErrorStacks = null;

		internal static bool IsShowErrorStacks
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.ShowErrorStacks))
#if DEBUG
					Global.ShowErrorStacks = "true";
#else
					Global.ShowErrorStacks = UtilityService.GetAppSetting("ShowErrorStacks", "false");
#endif
				return Global.ShowErrorStacks.IsEquals("true");
			}
		}

		static string SetErrorStatus = null;

		internal static bool IsSetErrorStatus
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.SetErrorStatus))
					Global.SetErrorStatus = UtilityService.GetAppSetting("SetErrorStatus", "false");
				return Global.SetErrorStatus.IsEquals("true");
			}
		}

		internal static void ShowError(this HttpContext context, int code, string message, string type, string stack, Exception inner)
		{
			// prepare
			var isDangerous = message.Contains("potentially dangerous");
			var json = new JObject()
			{
				{ "Message", isDangerous ? "Invalid" : message },
				{ "Type", type },
				{ "Verb", context.Request.HttpMethod },
				{ "CorrelationID", Base.AspNet.Global.GetCorrelationID(context.Items) }
			};

			if (!string.IsNullOrWhiteSpace(stack) && Global.IsShowErrorStacks)
				json.Add(new JProperty("Stack", stack));

			if (inner != null && Global.IsShowErrorStacks)
			{
				var inners = new JArray();
				var counter = 0;
				var exception = inner;
				while (exception != null)
				{
					counter++;
					inners.Add(new JObject()
					{
						{ "Message", "(" + counter + "): " + exception.Message },
						{ "Type", exception.GetType().ToString() },
						{ "Stack", exception.StackTrace }
					});
					exception = exception.InnerException;
				}

				if (counter > 0)
					json.Add(new JProperty("Inners", inners));
			}

			json = new JObject()
			{
				{ "Status", "Error" },
				{ "Error", json }
			};

			// status code
			if (Global.IsSetErrorStatus)
			{
				context.Response.TrySkipIisCustomErrors = true;
				context.Response.StatusCode = code < 1 ? 500 : code;
			}

			// response with JSON
			context.Response.Cache.SetNoStore();
			context.Response.ContentType = "application/json";
			context.Response.ClearContent();
			context.Response.Output.Write(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));

			// end response with dangerous requests
			if (isDangerous)
				context.Response.End();
		}

		internal static void ShowError(this HttpContext context, WampSharp.V2.Core.Contracts.WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			// prepare
			var details = exception.GetDetails(requestInfo);
			var code = details.Item1;
			var message = details.Item2;
			var type = details.Item3;
			var stack = details.Item4;
			var inner = details.Item5;
			var jsonException = details.Item6;

			// show error
			context.ShowError(code, message, type, stack, inner);

			// write logs
			if (writeLogs)
			{
				var logs = new List<string>() { "[" + type + "]: " + message };

				var fullStack = "";
				if (requestInfo != null)
					fullStack += "\r\n" + "==> Request:\r\n" + requestInfo.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None);

				if (jsonException != null)
					fullStack += "\r\n" + "==> Response:\r\n" + jsonException.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None);

				var correlationID = requestInfo != null
					? requestInfo.CorrelationID
					: Base.AspNet.Global.GetCorrelationID(context.Items);
				var serviceName = requestInfo != null
					? requestInfo.ServiceName
					: "unknown";
				var objectName = requestInfo != null
					? requestInfo.ObjectName
					: "unknown";

				Base.AspNet.Global.WriteLogs(correlationID, serviceName, objectName, logs, exception != null ? exception.StackTrace : "", fullStack);
			}
		}

		internal static void ShowError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			if (exception is WampSharp.V2.Core.Contracts.WampException)
				context.ShowError(exception as WampSharp.V2.Core.Contracts.WampException, requestInfo, writeLogs);

			else
			{
				// write logs
				if (writeLogs && exception != null)
					Base.AspNet.Global.WriteLogs(Base.AspNet.Global.GetCorrelationID(context.Items), "Errors", $"Error occurred while processing (Request: {requestInfo?.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None) ?? "None"})", exception);

				// show error
				var message = exception != null ? exception.Message : "Unknown error";
				var type = exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown";
				var stack = exception != null && Global.IsShowErrorStacks ? exception.StackTrace : null;
				var inner = exception != null && Global.IsShowErrorStacks ? exception.InnerException : null;
				context.ShowError(exception != null ? exception.GetHttpStatusCode() : 500, message, type, stack, inner);
			}
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();
			app.Context.ShowError(exception, null, true);
		}
		#endregion

		#region Session & User with JSON Web Token
		internal static Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer)
		{
			var appInfo = Base.AspNet.Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
			return new Session()
			{
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3,
			};
		}

		internal static string GetAccessToken(this User user)
		{
			return User.GetAccessToken(user, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);
		}

		internal static string GetJSONWebToken(this Session session, string accessToken = null)
		{
			return User.GetJSONWebToken(session.User.ID, accessToken ?? session.User.GetAccessToken(), session.SessionID, Base.AspNet.Global.AESKey, Base.AspNet.Global.GenerateJWTKey());
		}

		internal static string ParseJSONWebToken(this Session session, string jwt)
		{
			// parse JSON Web Token
			var userID = "";
			var accessToken = "";
			var sessionID = "";
			try
			{
				var info = User.ParseJSONWebToken(jwt, Base.AspNet.Global.AESKey, Base.AspNet.Global.GenerateJWTKey());
				userID = info.Item1;
				accessToken = info.Item2;
				sessionID = info.Item3;
			}
			catch (Exception)
			{
				throw;
			}

			// get user information
			try
			{
				session.User = User.ParseAccessToken(accessToken, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Access token is invalid)", ex);
			}

			if (!session.User.ID.Equals(userID))
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// assign identity of the session
			session.SessionID = sessionID;

			// return access token
			return accessToken;
		}
		#endregion

		#region Send & process inter-communicate message
		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			try
			{
				await Base.AspNet.Global.RTUService.SendInterCommunicateMessageAsync(message, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch { }
		}

		static void ProcessInterCommunicateMessage(CommunicateMessage message)
		{
			if (message.Type.Equals("Users#Session"))
			{
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<User>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;
				var accessToken = ((message.Data["Token"] as JValue).Value as string).Decrypt();

				Global.Cache.Remove("Session#" + sessionID);

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID }
				};

				(new Session()
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user
				}).UpdateSessionJson(json, accessToken);

				(new UpdateMessage()
				{
					Type = "Users#Session",
					DeviceID = deviceID,
					Data = json
				}).Publish();
			}
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public GlobalHandler() : base() { }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// real-time update
			if (context.IsWebSocketRequest)
				context.AcceptWebSocketRequest(RTU.ProcessRequestAsync);

			// static resources
			else if (context.Request.QueryString["request-of-static-resource"] != null)
			{
				// check "If-Modified-Since" request to reduce traffict
				var eTag = "StaticResource#" + context.Request.RawUrl.ToLower().GetMD5();
				if (context.Request.Headers["If-Modified-Since"] != null && eTag.Equals(context.Request.Headers["If-None-Match"]))
				{
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.StatusCode = (int)HttpStatusCode.NotModified;
					context.Response.StatusDescription = "Not Modified";
					context.Response.Headers.Add("ETag", "\"" + eTag + "\"");
					return;
				}

				// prepare
				var path = context.Request.QueryString["path"];
				if (string.IsNullOrWhiteSpace(path))
					path = "~/data-files/statics/geo/countries.json";

				if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				// process
				try
				{
					// get information of the requested file
					var filePath = "";
					if (!path.IsStartsWith("/statics/"))
						filePath = context.Server.MapPath(path);

					else
					{
						filePath = UtilityService.GetAppSetting("StaticFilesPath");
						if (string.IsNullOrEmpty(filePath))
							filePath = HttpRuntime.AppDomainAppPath + @"\data-files\statics";
						if (filePath.EndsWith(@"\"))
							filePath = filePath.Left(filePath.Length - 1);

						filePath += path.Replace("/statics/", "/").Replace("/", @"\");
					}

					// check exist
					var fileInfo = new FileInfo(filePath);
					if (!fileInfo.Exists)
						throw new FileNotFoundException();

					// set cache policy
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.Cache.SetExpires(DateTime.Now.AddDays(1));
					context.Response.Cache.SetSlidingExpiration(true);
					context.Response.Cache.SetOmitVaryStar(true);
					context.Response.Cache.SetValidUntilExpires(true);
					context.Response.Cache.SetLastModified(fileInfo.LastWriteTime);
					context.Response.Cache.SetETag(eTag);

					// prepare content
					var staticMimeType = MimeMapping.GetMimeMapping(fileInfo.Name);
					if (string.IsNullOrWhiteSpace(staticMimeType))
						staticMimeType = "text/plain";

					var staticContent = await UtilityService.ReadTextFileAsync(fileInfo).ConfigureAwait(false);
					if (staticMimeType.IsEndsWith("json"))
						staticContent = JObject.Parse(staticContent).ToString(Formatting.Indented);

					// write content
					context.Response.ContentType = staticMimeType;
					await context.Response.Output.WriteAsync(staticContent).ConfigureAwait(false);
				}
				catch (FileNotFoundException ex)
				{
					context.ShowError((int)HttpStatusCode.NotFound, $"Not found [{path}]", "FileNotFoundException", ex.StackTrace, ex.InnerException);
				}
				catch (Exception ex)
				{
					context.ShowError(ex);
				}
			}

			// APIs
			else
			{
				// prepare
				var serviceName = context.Request.QueryString["service-name"];

				// no information
				if (string.IsNullOrWhiteSpace(serviceName))
					context.ShowError(new InvalidRequestException());

				// external APIs
				else if (ExternalAPIs.APIs.ContainsKey(serviceName))
					await ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

				// internal APIs
				else
					await InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
			}
		}
	}
	#endregion

	#region Global.asax
	public class GlobalApp : HttpApplication
	{

		protected void Application_Start(object sender, EventArgs args)
		{
			Global.OnAppStart(sender as HttpContext);
		}

		protected void Application_BeginRequest(object sender, EventArgs args)
		{
			Global.OnAppBeginRequest(sender as HttpApplication);
		}

		protected void Application_PreRequestHandlerExecute(object sender, EventArgs args)
		{
			Global.OnAppPreHandlerExecute(sender as HttpApplication);
		}

		protected void Application_PreSendRequestHeaders(object sender, EventArgs args)
		{
			Global.OnAppPreSendHeaders(sender as HttpApplication);
		}

		protected void Application_EndRequest(object sender, EventArgs args)
		{
			Global.OnAppEndRequest(sender as HttpApplication);
		}

		protected void Application_Error(object sender, EventArgs args)
		{
			Global.OnAppError(sender as HttpApplication);
		}

		protected void Application_End(object sender, EventArgs args)
		{
			Global.OnAppEnd();
		}
	}
	#endregion

}
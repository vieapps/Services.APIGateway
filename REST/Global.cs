#region Related components
using System;
using System.Configuration;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public static class Global
	{

		#region Encryption keys
		static string _AESKey = null;
		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		public static string AESKey
		{
			get
			{
				if (Global._AESKey == null)
				{
					try
					{
						Global._AESKey = ConfigurationManager.AppSettings["AESKey"];
					}
					catch
					{
						Global._AESKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._AESKey))
						Global._AESKey = "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3";
				}
				return Global._AESKey;
			}
		}

		public static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, false, 256);
		}

		public static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		static string _JWTKey = null;
		/// <summary>
		/// Geths the key for working with JSON Web Token
		/// </summary>
		public static string JWTKey
		{
			get
			{
				if (Global._JWTKey == null)
				{
					try
					{
						Global._JWTKey = ConfigurationManager.AppSettings["JWTKey"];
					}
					catch
					{
						Global._JWTKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._JWTKey))
						Global._JWTKey = "VIEApps-49d8bd8c-Default-babc-JWT-43f4-Sign-bc30-Key-355b0891dc0f";
				}
				return Global._JWTKey;
			}
		}

		public static string GenerateJWTKey()
		{
			return Global.AESKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
		}

		static string _RSAKey = null;
		/// <summary>
		/// Geths the key for working with RSA
		/// </summary>
		public static string RSAKey
		{
			get
			{
				if (Global._RSAKey == null)
				{
					try
					{
						Global._RSAKey = ConfigurationManager.AppSettings["RSAKey"];
					}
					catch
					{
						Global._RSAKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._RSAKey))
						Global._RSAKey = "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";
				}
				return Global._RSAKey;
			}
		}

		static RSACryptoServiceProvider _RSA = null;

		internal static RSACryptoServiceProvider RSA
		{
			get
			{
				if (Global._RSA == null)
					try
					{
						Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey.Decrypt());
					}
					catch (Exception ex)
					{
						throw ex;
					}
				return Global._RSA;
			}
		}

		static string _RSAExponent = null;

		public static string RSAExponent
		{
			get
			{
				if (Global._RSAExponent == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAExponent = xmlDoc.DocumentElement.ChildNodes[1].InnerText.ToHexa(true);
				}
				return Global._RSAExponent;
			}
		}

		static string _RSAModulus = null;

		public static string RSAModulus
		{
			get
			{
				if (Global._RSAModulus == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAModulus = xmlDoc.DocumentElement.ChildNodes[0].InnerText.ToHexa(true);
				}
				return Global._RSAModulus;
			}
		}
		#endregion

		/*

		#region Start/End the app
		public static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			//var correlationId = Global.GetContextId(context);
			//Global.WriteLogs(correlationId, "VIEApps RSX", "*** Start the server app [Physical path: " + Global.GetPath("/") + "]");

			// setup default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// real-time services

			stopwatch.Stop();
			//Global.WriteLogs(correlationId, "VIEApps RSX", "*** The app is initialized in " + stopwatch.GetElapsedTimes() + " *********" + "\r\n");
		}

		public static void OnAppEnd()
		{
			//RTServices.CloseChannels();
			//Data.Statistics.FlushStatistics();
			//Global.FlushLogs();
		}
		#endregion

		#region Begin/End the request
		public static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.AddHeader("Access-Control-Allow-Origin", "*");

			// prepare
			var executionFilePath = app.Request.AppRelativeCurrentExecutionFilePath;
			if (executionFilePath.StartsWith("~/"))
				executionFilePath = executionFilePath.Right(executionFilePath.Length - 2);

			var executionFilePaths = executionFilePath.ToArray('/', true);

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.AddHeader("Access-Control-Allow-Methods", "HEAD,GET,POST,PUT,DELETE,OPTIONS");

				var allowHeaders = app.Context.Request.Headers.Get("Access-Control-Request-Headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.AddHeader("Access-Control-Allow-Headers", allowHeaders);

				return;
			}

			// prepare
			var origin = app.Context.Request.UrlReferrer != null
									? app.Context.Request.UrlReferrer.AbsoluteUri
									: app.Context.Request.Headers != null && app.Context.Request.Headers["Origin"] != null
										? app.Context.Request.Headers["Origin"]
										: app.Context.Request.Headers != null && app.Context.Request.Headers["x-app-platform"] != null
											? app.Context.Request.Headers["x-app-platform"]
											: app.Context.Request.QueryString != null && app.Context.Request.QueryString["x-app-platform"] != null
												? app.Context.Request.QueryString["x-app-platform"]
												: "";

			// bypass
			if (Global.BypassSegments.Contains(executionFilePaths[0].ToLower()))
			{
				app.Context.Response.Cache.SetNoStore();
				return;
			}

			// hidden segments
			else if (Global.HiddenSegments.Contains(executionFilePaths[0].ToLower()))
			{
				Global.WriteLogs("Error Catcher", new List<string>() {
						"Handle the request to hidden segments",
						"- " + app.Context.Request.HttpMethod + " : " + app.Context.Request.RawUrl,
						"- Origin: " + origin,
						"- IP: " + app.Context.Request.UserHostAddress,
						"- Agent: " + app.Context.Request.UserAgent,
					}, null, "Server.ForbidenRequests");

				Global.ShowError(app.Context, new InvalidRequestException());
				return;
			}

			// show error of 403/404
			else if (executionFilePaths[0].IsEquals("global.ashx")
				&& app.Context.Request.QueryString.Count > 0 && app.Context.Request.QueryString[0].IndexOf(";") > 0)
			{
				var elements = app.Context.Request.QueryString.ToString().UrlDecode().ToArray(';');
				var errorCode = elements[0];
				var errorUrl = elements[1].Replace(":80", "").Replace(":443", "");

				Global.WriteLogs("Error Catcher", new List<string>() {
						"Handle the invalid request",
						"- URL: " + errorUrl,
						"- Code: " + errorCode,
						"- Method: " + app.Context.Request.HttpMethod,
						"- Origin: " + origin,
						"- IP: " + app.Context.Request.UserHostAddress,
						"- Agent: " + app.Context.Request.UserAgent,
					}, null, "Server.404Requests");

				Global.ShowError(app.Context, errorCode.Equals("403") || errorCode.Equals("404") ? "Invalid" : "Unknown (" + errorCode + " : " + errorUrl + ")", errorCode.Equals("403") || errorCode.Equals("404") ? "InvalidRequestException" : "Unknown", "net.vieapps.books.Exceptions." + (errorCode.Equals("403") || errorCode.Equals("404") ? "InvalidRequestException" : "Unknown"), null, null);
				return;
			}

#if DEBUG || REQUESTLOGS
			Global.WriteLogs("VIEApps RSX", new List<string>() {
					"Begin process request [" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.RawUrl,
					"- Origin: " + origin,
					"- IP: " + app.Context.Request.UserHostAddress,
					"- Agent: " + app.Context.Request.UserAgent,
				}, null, "Server.Requests");

			if (!executionFilePaths[0].IsEquals("rtu"))
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}
#endif

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx?mode=" + executionFilePaths[0].GetANSIUri();
			if (executionFilePaths.Length > 1)
				url += "&name=" + executionFilePaths[1];

			if (executionFilePaths[0].IsEquals(Utils.MediaFolder) || executionFilePaths[0].IsEquals("cover"))
			{
				if (executionFilePaths.Length > 2)
					url += "&identifier=" + executionFilePaths[2];
				if (executionFilePaths.Length > 3)
					url += "&filename=" + executionFilePaths[3];
			}

			else if (executionFilePaths.Length > 2)
				url += "&json=" + executionFilePaths[2];

			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key))
					url += "&" + key + "=" + app.Request.QueryString[key].UrlEncode();

#if DEBUG
			Global.WriteLogs("VIEApps RSX", new List<string>()
				{
					"[" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.RawUrl,
					"- Path: " + executionFilePath,
					"- Query-String: " + app.Context.Request.QueryString.ToString(", ", "="),
					"- Rewrite URL to: " + url
				}, null, "Server.RewriteURLs");
#endif

			app.Context.RewritePath(url);
		}

		public static void OnAppEndRequest(HttpApplication app)
		{
#if DEBUG || REQUESTLOGS
			if (app == null || app.Context == null || app.Context.Request == null || app.Context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			else if (app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				Global.WriteLogs("VIEApps RSX", "End process request - Total times: " + (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes(), null, "Server.Requests");
			}
#endif
		}
		#endregion

		#region Pre excute handlers/send headers
		public static void OnAppPreHandlerExecute(HttpApplication app)
		{
			if (app == null || app.Context == null || app.Context.Request == null || app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Request.Headers["Accept-Encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
				return;

			var mode = app.Context.Request.QueryString["mode"];
			if (string.IsNullOrWhiteSpace(mode))
				return;

			else if (Global.BypassSegments.Contains(mode.ToLower()) || mode.IsEquals("media-files") || mode.IsEquals("cover") || mode.IsEquals("avatar") || mode.IsEquals("captcha"))
				return;

			else if (mode.IsEquals("ebooks") && app.Context.Request.QueryString["name"] != null && app.Context.Request.QueryString["name"].IsEquals("download"))
				return;

			// apply compression
			var previousStream = app.Response.Filter;
			acceptEncoding = acceptEncoding.ToLower();

			// deflate
			if (acceptEncoding.Contains("deflate") || acceptEncoding.Equals("*"))
			{
				app.Response.Filter = new DeflateStream(previousStream, CompressionMode.Compress);
				app.Response.AppendHeader("Content-Encoding", "deflate");
			}

			// gzip
			else if (acceptEncoding.Contains("gzip"))
			{
				app.Response.Filter = new GZipStream(previousStream, CompressionMode.Compress);
				app.Response.AppendHeader("Content-Encoding", "gzip");
			}
		}

		public static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("Allow");
			app.Context.Response.Headers.Remove("Public");
			app.Context.Response.Headers.Remove("X-Powered-By");

			// add special header
			if (app.Response.Headers["Server"] != null)
				app.Response.Headers.Set("Server", "VIEApps RSX");
			else
				app.Response.Headers.Add("Server", "VIEApps RSX");
		}
		#endregion

		#region Handle errors of the app
		public static void ShowError(HttpContext context, string message, string type, string typeNamespace, string stackTrace, Exception innerException)
		{
			// prepare
			var error = new JObject()
			{
				{ "Message", message.Contains("potentially dangerous") ? "Invalid" : message },
				{ "Type", type },
				{ "Namespace", typeNamespace }
			};

			if (!string.IsNullOrWhiteSpace(stackTrace))
				error.Add(new JProperty("Stack", stackTrace));

			if (innerException != null)
			{
				var inners = new JArray();
				var counter = 0;
				var exception = innerException;
				while (exception != null)
				{
					counter++;
					inners.Add(new JObject()
					{
						{ "Inner", "(" + counter + "): " + exception.Message + " [" + exception.GetType().ToString() + "]" },
						{ "Stack", exception.StackTrace }
					});
					exception = exception.InnerException;
				}

				if (counter > 0)
					error.Add(new JProperty("Inners", inners));
			}

			// response with JSON
			context.Response.ContentType = "application/json";
			context.Response.Cache.SetNoStore();
			context.Response.ClearContent();
			context.Response.Output.Write((new JObject() { { "Status", "Error" }, { "Error", error } }).ToString(Formatting.None));

			if (message.Contains("potentially dangerous"))
				context.Response.End();
		}

		public static void ShowError(HttpContext context, Exception ex)
		{
			var type = "Unknown";
			var typeNamespace = "net.vieapps.books.Exceptions.Unknown";
			string stack = null;
			Exception innerException = null;
			if (ex != null)
			{
				typeNamespace = ex.GetType().ToString();
				type = typeNamespace.ToArray('.').Last();
#if DEBUG
				stack = ex.StackTrace;
				innerException = ex.InnerException;
#endif
			}
			Global.ShowError(context, ex != null ? ex.Message : "Unknown", type, typeNamespace, stack, innerException);
		}

		public static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();

			Global.WriteLogs("Error Catcher", new List<string>(), exception, null);
			Global.ShowError(app.Context, exception);
		}
		#endregion
		
		*/
	}

	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public override bool IsReusable { get { return true; } }

		#region Process request
		public override async Task ProcessRequestAsync(HttpContext context)
		{

		}
		#endregion

	}

}
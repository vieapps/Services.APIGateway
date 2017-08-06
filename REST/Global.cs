#region Related components
using System;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Rpc;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Global
	{

		#region Encryption keys
		static string _AESKey = null;
		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		internal static string AESKey
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

		internal static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, false, 256);
		}

		internal static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		static string _JWTKey = null;
		/// <summary>
		/// Geths the key for working with JSON Web Token
		/// </summary>
		internal static string JWTKey
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

		internal static string GenerateJWTKey()
		{
			return Global.JWTKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
		}

		static string _RSAKey = null;
		/// <summary>
		/// Geths the key for working with RSA
		/// </summary>
		internal static string RSAKey
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

		internal static string RSAExponent
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

		internal static string RSAModulus
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

		#region Encrypt/Decrypt
		internal static string AESEncrypt(string data, string key = null, bool toHexa = false)
		{
			return data.Encrypt(string.IsNullOrWhiteSpace(key) ? Global.AESKey : key, toHexa);
		}

		internal static string AESDecrypt(string data, string key = null, bool isHexa = false)
		{
			return data.Decrypt(string.IsNullOrWhiteSpace(key) ? Global.AESKey : key, isHexa);
		}

		internal static string RSAEncrypt(string data)
		{
			return CryptoService.RSAEncrypt(Global.RSA, data);
		}

		internal static string RSADecrypt(string data)
		{
			return CryptoService.RSADecrypt(Global.RSA, data);
		}
		#endregion

		#region WAMP channels
		internal static IWampChannel IncommingChannel = null, OutgoingChannel = null;
		internal static bool ChannelAreClosedBySystem = false;

		static Tuple<string, string, bool> GetLocationInfo()
		{
			var address = ConfigurationManager.AppSettings["RouterAddress"];
			if (string.IsNullOrWhiteSpace(address))
				address = "ws://127.0.0.1:26429/";

			var realm = ConfigurationManager.AppSettings["RouterRealm"];
			if (string.IsNullOrWhiteSpace(realm))
				realm = "VIEAppsRealm";

			var mode = ConfigurationManager.AppSettings["RouterChannelsMode"];
			if (string.IsNullOrWhiteSpace(mode))
				mode = "MsgPack";

			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		internal static async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.IncommingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.IncommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.IncommingChannel.Open();
		}

		internal static void CloseIncomingChannel()
		{
			if (Global.IncommingChannel != null)
			{
				Global.IncommingChannel.Close("The incoming channel is closed when stop the API Gateway REST Service", new GoodbyeDetails());
				Global.IncommingChannel = null;
			}
		}

		internal static void ReOpenIncomingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.IncommingChannel != null)
				(new WampChannelReconnector(Global.IncommingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await Global.IncommingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.OutgoingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.OutgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.OutgoingChannel.Open();
		}

		internal static void CloseOutgoingChannel()
		{
			if (Global.OutgoingChannel != null)
			{
				Global.OutgoingChannel.Close("The outgoing channel is closed when stop the API Gateway REST Service", new GoodbyeDetails());
				Global.OutgoingChannel = null;
			}
		}

		internal static void ReOpenOutgoingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.OutgoingChannel != null)
				(new WampChannelReconnector(Global.OutgoingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await Global.OutgoingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenChannelsAsync()
		{
			await Global.OpenIncomingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The incoming connection is established" + "\r\n" + " - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The incoming connection is broken because the router is not found or the router is refused" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelAreClosedBySystem)
							Global.WriteLogs("The incoming connection is closed" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenIncomingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the incoming connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await Global.OpenOutgoingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The outgoing connection is established" + "\r\n" + " - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The outgoing connection is broken because the router is not found or the router is refused" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelAreClosedBySystem)
							Global.WriteLogs("The outgoing connection is closed" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenOutgoingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the outgoing connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);
		}
		#endregion

		#region Working with logs
		internal static string GetCorrelationID(IDictionary items)
		{
			if (items == null)
				return UtilityService.GetUUID();

			var id = items.Contains("Correlation-ID")
				? items["Correlation-ID"] as string
				: null;

			if (string.IsNullOrWhiteSpace(id))
			{
				id = UtilityService.GetUUID();
				items.Add("Correlation-ID", id);
			}

			return id;
		}

		internal static string GetCorrelationID()
		{
			return Global.GetCorrelationID(HttpContext.Current?.Items);
		}

		static IManagementService ManagementService = null;

		internal static async Task InitializeManagementServiceAsync()
		{
			if (Global.ManagementService == null)
			{
				await Global.OpenOutgoingChannelAsync();
				Global.ManagementService = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IManagementService>();
			}
		}

		internal static async Task WriteLogsAsync(string correlationID, string objectName, List<string> logs, Exception exception = null, string serviceName = null)
		{
			// prepare
			var stack = "";
			if (exception != null)
			{
				stack = exception.StackTrace;
				var inner = exception.InnerException;
				int counter = 0;
				while (inner != null)
				{
					counter++;
					stack += "\r\n" + "-> Inner (" + counter.ToString() + "): ---->>>>" + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
				}
				stack += "\r\n" + "-------------------------------------" + "\r\n";
			}

			// write logs
			try
			{
				await Global.InitializeManagementServiceAsync();
				await Global.ManagementService.WriteLogsAsync(correlationID, string.IsNullOrWhiteSpace(objectName) ? "APIGateway" : serviceName, (string.IsNullOrWhiteSpace(objectName) ? "APIGateway" : objectName).ToLower(), logs, stack);
			}
			catch { }
		}

		internal static async Task WriteLogsAsync(string correlationID, string objectName, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			await Global.WriteLogsAsync(correlationID, objectName, logs, exception);
		}

		internal static async Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), null, logs, exception);
		}

		internal static async Task WriteLogsAsync(string log, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), null, log, exception);
		}

		internal static void WriteLogs(string correlationID, string objectName, List<string> logs, Exception exception = null, string serviceName = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, objectName, logs, exception, serviceName);
			}).ConfigureAwait(false);
		}

		internal static void WriteLogs(string correlationID, string objectName, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			Global.WriteLogs(correlationID, objectName, logs, exception);
		}

		internal static void WriteLogs(List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, logs, exception);
		}

		internal static void WriteLogs(string log, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, log, exception);
		}
		#endregion

		#region Start/End the app
		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			Task.Run(async () =>
			{
				await Global.OpenChannelsAsync();
			}).ConfigureAwait(false);

			stopwatch.Stop();
			Global.WriteLogs("*** The API Gateway REST server is ready for serving. The app is initialized in " + stopwatch.GetElapsedTimes());
		}

		internal static void OnAppEnd()
		{
			RTU.CancellationTokenSource.Cancel();
			RTU.StopSubscribers();
			Global.ChannelAreClosedBySystem = true;
			Global.CloseIncomingChannel();
			Global.CloseOutgoingChannel();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.AddHeader("Access-Control-Allow-Origin", "*");

			// prepare
			var executionFilePath = app.Request.AppRelativeCurrentExecutionFilePath;
			if (executionFilePath.StartsWith("~/"))
				executionFilePath = executionFilePath.Right(executionFilePath.Length - 2);

			var executionFilePaths = string.IsNullOrEmpty(executionFilePath)
				? new string[] {""}
				: executionFilePath.ToArray('/', true);

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.AddHeader("Access-Control-Allow-Methods", "HEAD,GET,POST,PUT,DELETE,OPTIONS");

				var allowHeaders = app.Context.Request.Headers.Get("Access-Control-Request-Headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.AddHeader("Access-Control-Allow-Headers", allowHeaders);

				return;
			}

#if DEBUG || REQUESTLOGS
			var origin = app.Context.Request.UrlReferrer != null
				? app.Context.Request.UrlReferrer.AbsoluteUri
				: app.Context.Request.Headers != null && app.Context.Request.Headers["origin"] != null
					? app.Context.Request.Headers["origin"]
					: null;

			if (string.IsNullOrWhiteSpace(origin))
			{
				var appName = app.Context.Request.Headers != null && app.Context.Request.Headers["x-app-name"] != null
					? app.Context.Request.Headers["x-app-name"]
					: app.Context.Request.QueryString != null && app.Context.Request.QueryString["x-app-name"] != null
						? app.Context.Request.QueryString["x-app-name"]
						: "";

				var appPlatform = app.Context.Request.Headers != null && app.Context.Request.Headers["x-app-platform"] != null
					? app.Context.Request.Headers["x-app-platform"]
					: app.Context.Request.QueryString != null && app.Context.Request.QueryString["x-app-platform"] != null
						? app.Context.Request.QueryString["x-app-platform"]
						: "";

				origin = (!string.IsNullOrWhiteSpace(appName) && !string.IsNullOrWhiteSpace(appPlatform)
						? appName + "/" + appPlatform
						: "")
					+ " - " + app.Context.Request.UserHostAddress;
			}

			Global.WriteLogs(new List<string>() {
					"Begin process [" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.RawUrl,
					"- Origin: " + origin,
					"- IP: " + app.Context.Request.UserHostAddress,
					"- Agent: " + app.Context.Request.UserAgent,
				});

			if (!executionFilePaths[0].IsEquals("rtu"))
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}
#endif

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx?service-name=" + executionFilePaths[0].GetANSIUri();
			if (executionFilePaths.Length > 1)
				url += "&object-name=" + executionFilePaths[1].GetANSIUri();
			if (executionFilePaths.Length > 2)
				url += "&object-identity=" + executionFilePaths[2].GetANSIUri();

			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key))
					url += "&" + key + "=" + app.Request.QueryString[key].UrlEncode();

#if DEBUG || REWRITELOGS
			Global.WriteLogs(new List<string>()
				{
					"[" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.RawUrl,
					"=> " + url
				});
#endif

			app.Context.RewritePath(url);
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
#if DEBUG || REQUESTLOGS
			if (app == null || app.Context == null || app.Context.Request == null || app.Context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			else if (app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				Global.WriteLogs("End process - Execution times: " + (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes());
			}
#endif
		}
		#endregion

		#region Pre excute handlers/send headers
		internal static void OnAppPreHandlerExecute(HttpApplication app)
		{
			if (app == null || app.Context == null || app.Context.Request == null || app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Request.Headers["Accept-Encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
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

		internal static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("Allow");
			app.Context.Response.Headers.Remove("Public");
			app.Context.Response.Headers.Remove("X-Powered-By");

			// add special header
			if (app.Response.Headers["Server"] != null)
				app.Response.Headers.Set("Server", "VIEApps API Gateway");
			else
				app.Response.Headers.Add("Server", "VIEApps API Gateway");
		}
		#endregion

		#region Handle errors
		static string ShowErrorStacks = null;

		internal static bool IsShowErrorStacks
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.ShowErrorStacks))
#if DEBUG
					Global.ShowErrorStacks = "true";
#else
					try
					{
						Global.ShowErrorStacks = ConfigurationManager.AppSettings["ShowErrorStacks"];
					}
					catch
					{
						Global.ShowErrorStacks = "false";
					}
#endif
				return Global.ShowErrorStacks.IsEquals("true");
			}
		}

		internal static void ShowError(HttpContext context, string message, string type, string stack, Exception inner)
		{
			// prepare
			var json = new JObject()
			{
				{ "Message", message.Contains("potentially dangerous") ? "Invalid" : message },
				{ "Type", type },
				{ "Verb", context.Request.HttpMethod },
				{ "CorrelationID", Global.GetCorrelationID(context.Items) }
			};

			if (!string.IsNullOrWhiteSpace(stack) && Global.IsShowErrorStacks)
				json.Add(new JProperty("StackTrace", stack));

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
						{ "StackTrace", exception.StackTrace }
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

			// response with JSON
			context.Response.ContentType = "application/json";
			context.Response.Cache.SetNoStore();
			context.Response.ClearContent();
			context.Response.Output.Write(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));

			if (message.Contains("potentially dangerous"))
				context.Response.End();
		}

		static JObject GetJsonException(JObject exception)
		{
			var json = new JObject()
			{
				{ "Message", exception["Message"] },
				{ "Type", exception["ClassName"] },
				{ "Method", exception["ExceptionMethod"] },
				{ "Source", exception["Source"] },
				{ "StackTrace", exception["StackTraceString"] },
			};

			var inner = exception["InnerException"];
			if (inner != null && inner is JObject)
				json.Add(new JProperty("InnerException", Global.GetJsonException(inner as JObject)));

			return json;
		}

		internal static void ShowError(HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			var message = "";
			var type = "";
			var stack = "";
			Exception inner = null;
			JObject jsonException = null;

			if (exception.ErrorUri.Equals("wamp.error.no_such_procedure"))
			{
				if (exception.Arguments.Length > 0 && exception.Arguments[0] != null && exception.Arguments[0] is JValue)
				{
					message = (exception.Arguments[0] as JValue).Value.ToString();
					var start = message.IndexOf("'");
					var end = message.IndexOf("'", start + 1);
					message = "The requested service is not found [" + message.Substring(start + 1, end - start - 1).Replace("'", "") + "]";
				}
				else
					message = "The requested service is not found";

				type = "ServiceNotFoundException";
				stack = exception.StackTrace;
				inner = exception;
			}
			else if (exception.ErrorUri.Equals("wamp.error.runtime_error"))
			{
				if (exception.Arguments != null && exception.Arguments.Length > 0 && exception.Arguments[0] != null && exception.Arguments[0] is JObject)
					foreach (var info in exception.Arguments[0] as JObject)
					{
						if (info.Value != null && info.Value is JValue && (info.Value as JValue).Value != null)
							stack += (stack.Equals("") ? "" : "\r\n" + "----- Inner (" + info.Key + ") --------------------" + "\r\n")
								+ (info.Value as JValue).Value.ToString();
					}

				if (requestInfo == null && exception.Arguments != null && exception.Arguments.Length > 2 && exception.Arguments[2] != null && exception.Arguments[2] is JObject)
				{
					var info = (exception.Arguments[2] as JObject).First;
					if (info != null && info is JProperty && (info as JProperty).Name.Equals("RequestInfo") && (info as JProperty).Value != null && (info as JProperty).Value is JObject)
						requestInfo = ((info as JProperty).Value as JToken).FromJson<RequestInfo>();
				}

				jsonException = exception.Arguments != null && exception.Arguments.Length > 4 && exception.Arguments[4] != null && exception.Arguments[4] is JObject
					? Global.GetJsonException(exception.Arguments[4] as JObject)
					: null;

				message = jsonException != null
					? (jsonException["Message"] as JValue).Value.ToString()
					: "Error occurred while processing with the service [net.vieapps.services." + (requestInfo != null ? requestInfo.ServiceName.ToLower() : "unknown") + "]";

				type = jsonException != null
					? (jsonException["Type"] as JValue).Value.ToString().ToArray('.').Last()
					: "ServiceOperationException";

				inner = exception;
			}

			else
			{
				message = exception.Message;
				type = exception.GetType().ToString().ToArray('.').Last();
				stack = exception.StackTrace;
				inner = exception.InnerException;
			}

			// show error
			Global.ShowError(context, message, type, stack, inner);

			// write logs
			if (writeLogs)
			{
				var logs = new List<string>()
				{
					message,
					"Type: " + type
				};

				if (!string.IsNullOrWhiteSpace(stack))
					logs.Add("StackTrace:" + stack);

				if (requestInfo != null)
					logs.Add("Request:\r\n" + requestInfo.ToJson().ToString(Formatting.Indented));

				if (jsonException != null)
					logs.Add("Details:\r\n" + jsonException.ToString(Formatting.Indented));

				var correlationID = requestInfo != null ? requestInfo.CorrelationID : Global.GetCorrelationID(context.Items);
				var serviceName = requestInfo != null ? requestInfo.ServiceName : "unknown";
				var objectName = requestInfo != null ? requestInfo.ObjectName : "unknown";

				Global.WriteLogs(correlationID, objectName, logs, inner, serviceName);
			}
		}

		internal static void ShowError(HttpContext context, Exception exception)
		{
			if (exception is WampException)
				Global.ShowError(context, exception as WampException, null);

			else
			{
				var type = "Unknown";
				string stack = null;
				Exception inner = null;
				if (exception != null)
				{
					type = exception.GetType().ToString().ToArray('.').Last();
					if (Global.IsShowErrorStacks)
					{
						stack = exception.StackTrace;
						inner = exception.InnerException;
					}
				}
				Global.ShowError(context, exception != null ? exception.Message : "Unknown", type, stack, inner);
			}
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();

			Global.WriteLogs("", exception);
			Global.ShowError(app.Context, exception);
		}
		#endregion

		#region Session & User with JSON Web Token
		internal static Session GetSession(NameValueCollection header, NameValueCollection query, string ipAddress, string agentString = null, Uri urlReferrer = null)
		{
			var session = new Session()
			{
				IP = ipAddress,
				AppAgent = agentString
			};

			session.DeviceID = header["x-device-id"];
			if (string.IsNullOrWhiteSpace(session.DeviceID))
				session.DeviceID = query["x-device-id"];

			session.AppName = header["x-app-name"];
			if (string.IsNullOrWhiteSpace(session.AppName))
				session.AppName = query["x-app-name"];

			session.AppPlatform = header["x-app-name"];
			if (string.IsNullOrWhiteSpace(session.AppPlatform))
				session.AppPlatform = query["x-app-platform"];

			if (string.IsNullOrWhiteSpace(session.AppName) && string.IsNullOrWhiteSpace(session.AppPlatform) && !string.IsNullOrWhiteSpace(agentString))
			{
				session.AppName = "Generic App";
				if (agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod"))
					session.AppPlatform = "iOS";
				else if (agentString.IsContains("Android"))
					session.AppPlatform = "Android";
				else if (agentString.IsContains("Android"))
					session.AppPlatform = "Android";
				else if (agentString.IsContains("Windows Phone"))
					session.AppPlatform = "Windows Phone";
				else if (agentString.IsContains("BlackBerry") || agentString.IsContains("BB10"))
					session.AppPlatform = "BlackBerry";
				else if (agentString.IsContains("IEMobile") || agentString.IsContains("Opera Mini"))
					session.AppPlatform = "Mobile";
				else
					session.AppPlatform = "Desktop";
				session.AppPlatform += " PWA";
			}

			session.AppOrigin = header["origin"];
			if (string.IsNullOrWhiteSpace(session.AppOrigin))
				session.AppOrigin = urlReferrer?.AbsoluteUri;
			if (string.IsNullOrWhiteSpace(session.AppOrigin))
				session.AppOrigin = session.IP;

			return session;
		}

		internal static string GetAccessToken(string userID, SystemRole userRole, List<string> userRoles, List<Privilege> privileges)
		{
			var token = new JObject()
			{
				{ "ID", userID },
				{ "Role", userRole.ToString() }
			};

			if (userRoles != null && userRoles.Count > 0)
				token.Add(new JProperty("Roles", userRoles));

			if (privileges != null && privileges.Count > 0)
				token.Add(new JProperty("Privileges", privileges));

			var key = UtilityService.GetUUID();
			token = new JObject()
			{
				{ "Key", Global.RSAEncrypt(key) },
				{ "Data", token.ToString(Formatting.None).Encrypt(key) }
			};

			return token.ToString(Formatting.None).Encrypt(Global.AESKey);
		}

		internal static string GetAccessToken(this User user)
		{
			return Global.GetAccessToken(user.ID, user.Role, user.Roles, user.Privileges);
		}

		internal static User GetUser(this string accessToken)
		{
			// decrypt
			string decrypted = "";
			try
			{
				decrypted = accessToken.Decrypt(Global.AESKey);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// parse JSON
			JObject token = null;
			try
			{
				token = JObject.Parse(decrypted);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot parse the JSON", ex);
			}

			// check
			if (token["Key"] == null || token["Data"] == null)
				throw new InvalidTokenException();

			// decrypt key
			try
			{
				decrypted = Global.RSADecrypt((token["Key"] as JValue).Value.ToString());
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// decrypt JSON
			try
			{
				decrypted = (token["Data"] as JValue).Value.ToString().Decrypt(decrypted);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// serialize from JSON
			try
			{
				return decrypted.FromJson<User>();
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot deserialize parse the JSON", ex);
			}
		}

		static string GetSignature(this string sessionID, string accessToken, string algorithm = "HS512")
		{
			var data = accessToken + "@" + sessionID;
			var key = CryptoService.DefaultEncryptionKey;

			algorithm = algorithm ?? "HS512";
			switch (algorithm.ToLower())
			{
				case "hs1":
					return data.GetHMACSHA1(key, false);

				case "hs256":
					return data.GetHMACSHA256(key, false);

				case "hs384":
					return data.GetHMACSHA384(key, false);

				default:
					return data.GetHMACSHA512(key, false);
			}
		}

		internal static string GetJSONWebToken(this Session session, string accessToken = null)
		{
			accessToken = accessToken ?? session.User.GetAccessToken();
			var payload = new JObject()
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "jti", session.SessionID.Encrypt(Global.AESKey.Reverse()) },
				{ "uid", session.User.ID },
				{ "jtk", accessToken },
				{ "jts", session.SessionID.GetSignature(accessToken) }
			};
			return JSONWebToken.Encode(payload, Global.GenerateJWTKey());
		}

		internal static async Task<string> ParseJSONWebTokenAsync(this Session session, string jwt, Func<Session, Task> checkAsync = null)
		{
			// parse JSON Web Token
			JObject payload = null;
			try
			{
				payload = JSONWebToken.DecodeAsJObject(jwt, Global.GenerateJWTKey());
			}
			catch (InvalidTokenSignatureException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException(ex);
			}

			// check issued time
			var issuedAt = payload["iat"] != null
				? (long)(payload["iat"] as JValue).Value
				: DateTime.Now.AddDays(-30).ToUnixTimestamp();
			if (DateTime.Now.ToUnixTimestamp() - issuedAt > 30)
				throw new TokenExpiredException();

			// get session identity
			var sessionID = payload["jti"] != null
				? (payload["jti"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(sessionID))
				throw new InvalidTokenException("Token is invalid (Identity is invalid)");

			try
			{
				sessionID = sessionID.Decrypt(Global.AESKey.Reverse());
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Identity is invalid)", ex);
			}

			// get access token
			var accessToken = payload["jtk"] != null
				? (payload["jtk"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(accessToken))
				throw new InvalidTokenException("Token is invalid (Access token is invalid)");

			var signature = payload["jts"] != null
				? (payload["jts"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(signature) || !signature.Equals(sessionID.GetSignature(accessToken)))
				throw new InvalidTokenSignatureException("Token is invalid (Signature is invalid)");

			var userID = (payload["uid"] as JValue).Value as string;
			if (userID == null)
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// get user information
			try
			{
				session.User = accessToken.GetUser();
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Access token is invalid)", ex);
			}

			if (!session.User.ID.Equals(userID))
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// check to see the session is registered or not
			session.SessionID = sessionID;
			if (checkAsync != null)
				await checkAsync(session);

			// return access token
			return accessToken;
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public override bool IsReusable { get { return true; } }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// real-time update
			else if (context.IsWebSocketRequest)
				context.AcceptWebSocketRequest(RTU.ProcessRequestAsync);

			// APIs
			else
			{
				// no information
				if (string.IsNullOrWhiteSpace(context.Request.QueryString["service-name"]))
					Global.ShowError(context, new InvalidRequestException());

				// external APIs
				else if (ExternalAPIs.APIs.ContainsKey(context.Request.QueryString["service-name"]))
					await ExternalAPIs.ProcessRequestAsync(context);

				// internal APIs
				else
					await InternalAPIs.ProcessRequestAsync(context);
			}
		}
	}
	#endregion

	#region Global.asax
	public class GlobalApp : HttpApplication
	{

		protected void Application_Start(object sender, EventArgs e)
		{
			Global.OnAppStart(sender as HttpContext);
		}

		protected void Application_BeginRequest(object sender, EventArgs e)
		{
			Global.OnAppBeginRequest(sender as HttpApplication);
		}

		protected void Application_PreRequestHandlerExecute(object sender, EventArgs e)
		{
			Global.OnAppPreHandlerExecute(sender as HttpApplication);
		}

		protected void Application_PreSendRequestHeaders(object sender, EventArgs e)
		{
			Global.OnAppPreSendHeaders(sender as HttpApplication);
		}

		protected void Application_EndRequest(object sender, EventArgs e)
		{
			Global.OnAppEndRequest(sender as HttpApplication);
		}

		protected void Application_Error(object sender, EventArgs e)
		{
			Global.OnAppError(sender as HttpApplication);
		}

		protected void Application_End(object sender, EventArgs e)
		{
			Global.OnAppEnd();
		}
	}
	#endregion

}
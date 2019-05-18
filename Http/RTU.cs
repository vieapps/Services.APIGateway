#region Related components
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Dynamic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Security;
using net.vieapps.Components.WebSockets;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{
		public static Components.WebSockets.WebSocket WebSocket { get; private set; }

		public static ILogger Logger { get; set; }

		public static void Initialize()
		{
			RTU.WebSocket = new Components.WebSockets.WebSocket(Components.Utility.Logger.GetLoggerFactory(), Global.CancellationTokenSource.Token)
			{
				OnError = (websocket, exception) => Global.WriteLogs(RTU.Logger, "Http.InternalAPIs", $"Got an error while processing => {exception.Message} ({websocket?.ID} {websocket?.RemoteEndPoint})", exception),
				OnConnectionEstablished = (websocket) => Task.Run(() => websocket.WhenConnectionIsEstablishedAsync()).ConfigureAwait(false),
				OnConnectionBroken = (websocket) => Task.Run(() => websocket.WhenConnectionIsBrokenAsync()).ConfigureAwait(false),
				OnMessageReceived = (websocket, result, data) => Task.Run(() => websocket.WhenMessageIsReceivedAsync(result, data)).ConfigureAwait(false),
				KeepAliveInterval = TimeSpan.FromSeconds(45)
			};
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is initialized - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes - Keep-Alive interval: {RTU.WebSocket.KeepAliveInterval.TotalSeconds} second(s)");
		}

		public static void Dispose()
		{
			RTU.WebSocket.Dispose();
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is stopped");
		}

		static async Task WhenConnectionIsEstablishedAsync(this ManagedWebSocket websocket)
		{
			// update the state
			websocket.Set("State", "Initializing");

			// prepare
			var query = websocket.RequestUri.ParseQuery();
			var headers = websocket.Headers;
			var correlationID = UtilityService.NewUUID;
			Session session = null;
			try
			{
				var request = new ExpandoObject();
				if (query.ContainsKey("x-request"))
					try
					{
						request = query["x-request"].Url64Decode().ToExpandoObject();
					}
					catch (Exception ex)
					{
						throw new InvalidRequestException($"Request is invalid => {ex.Message}", ex);
					}

				if (!headers.TryGetValue("x-app-token", out var appToken))
					appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
					throw new TokenNotFoundException("Token is not found");

				session = Global.GetSession(headers, null, $"{(websocket.RemoteEndPoint as IPEndPoint).Address}");
				session.DeviceID = headers.TryGetValue("x-device-id", out string deviceID) ? deviceID : request.Get("x-device-id", session.DeviceID);
				session.AppName = headers.TryGetValue("x-app-name", out string appName) ? appName : request.Get("x-app-name", session.AppName);
				session.AppPlatform = headers.TryGetValue("x-app-platform", out string appPlatform) ? appPlatform : request.Get("x-app-platform", session.AppPlatform);
				session.IP = (websocket.RemoteEndPoint as IPEndPoint).Address.ToString();

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				await Global.UpdateWithAuthenticateTokenAsync(session, appToken, null, null, null, RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false);
				if (!await session.IsSessionExistAsync(RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

				websocket.Set("Token", JSONWebToken.DecodeAsJson(appToken, Global.JWTKey));
			}
			catch (Exception ex)
			{
				var exception = ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException || ex is InvalidRequestException
					? ex
					: new InvalidRequestException($"Request is invalid => {ex.Message}", ex);
				var additionalMsg = $"Credential error => {ex.Message}\r\n- Query String:\r\n\t{query.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}\r\n- Headers:\r\n\t{websocket.Headers.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}";
				await websocket.SendAsync(exception, null, correlationID, null, additionalMsg, "Http.WebSockets.Errors").ConfigureAwait(false);
				await RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.InvalidPayloadData, ex is InvalidRequestException ? ex.Message : $"Request is invalid => {ex.Message}").ConfigureAwait(false);
				return;
			}

			// update related information
			websocket.Set("Session", session);
			await websocket.PrepareConnectionInfoAsync(correlationID, session).ConfigureAwait(false);

			// wait for few times before connecting to API Gateway Router because RxNET needs that
			if (query.ContainsKey("x-restart"))
			{
				// send knock message
				await websocket.SendAsync(new UpdateMessage { Type = "Knock" }).ConfigureAwait(false);

				// wait for a few times
				try
				{
					await Task.Delay(345, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.EndpointUnavailable, ex.Message).ConfigureAwait(false);
					return;
				}

				// re-update status of the session
				await session.SendSessionStateAsync(true, correlationID).ConfigureAwait(false);
			}

			// subscribe an updater to push messages to client device
			websocket.Set("Updater", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<UpdateMessage>("messages.update")
				.Subscribe(
					async message =>
					{
						if ("Disconnected".IsEquals(websocket.Get<string>("State")) || session.DeviceID.IsEquals(message.ExcludedDeviceID) || (!"*".Equals(message.DeviceID) && !session.DeviceID.IsEquals(message.DeviceID)))
							return;
						var correlatedID = UtilityService.NewUUID;
						try
						{
							await websocket.SendAsync(message).ConfigureAwait(false);
							if (Global.IsDebugLogEnabled)
								await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
									$"Successfully push a message to the subscriber's device" + "\r\n" +
									$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
									$"- Type: {message.Type}" + "\r\n" +
									$"- Message: {message.Data.ToString(Formatting.None)}"
								, null,  Global.ServiceName, LogLevel.Information, correlatedID).ConfigureAwait(false);
						}
						catch (ObjectDisposedException) { }
						catch (Exception ex)
						{
							await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
								$"Error occurred while pushing a message to the subscriber's device => {ex.Message}" + "\r\n" +
								$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
								$"- Type: {message.Type}" + "\r\n" +
								$"- Message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
							, ex, Global.ServiceName, LogLevel.Error, correlatedID).ConfigureAwait(false);
						}
					},
					async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an updating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// subscribe a communicator to update related information
			websocket.Set("Communicator", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<CommunicateMessage>("messages.services.apigateway")
				.Subscribe(
					async message =>
					{
						if ("Disconnected".IsEquals(websocket.Get<string>("State")))
							return;
						var correlatedID = UtilityService.NewUUID;
						if (session.SessionID.IsEquals(message.Data.Get<string>("SessionID")))
							try
							{
								// patch the session (update session with new identity and privileges)
								if (message.Type.IsEquals("Session#Patch"))
								{
									var authenticateToken = message.Data.Get<string>("AuthenticateToken");
									var encryptedSessionID = message.Data.Get<string>("EncryptedID");
									await Global.UpdateWithAuthenticateTokenAsync(session, authenticateToken, null, null, null, RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false);
									if (!await session.IsSessionExistAsync(RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false))
										throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
									else if (!session.SessionID.Equals(session.GetDecryptedID(encryptedSessionID, Global.EncryptionKey, Global.ValidationKey)))
										throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
									await websocket.PrepareConnectionInfoAsync(correlatedID, session).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
											$"Successfully process an inter-communicate message (patch session - {message.Data.Get<string>("SessionID")} => {session.SessionID})" + "\r\n" +
											$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
											$"- Type: {message.Type}" + "\r\n" +
											$"- Message: {message.Data.ToString(Formatting.None)}"
										, null, Global.ServiceName, LogLevel.Information, correlatedID).ConfigureAwait(false);
								}

								// update the session with new users' privileges => new access token
								else if (message.Type.IsEquals("Session#Update"))
								{
									session.User = message.Data["User"] == null ? session.User : message.Data.Get<JObject>("User").Copy<User>();
									session.Verified = message.Data.Get<bool>("Verified");
									await websocket.SendAsync(new UpdateMessage
									{
										Type = "Users#Session#Update",
										Data = session.GetSessionJson()
									}).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
											$"Successfully process an inter-communicate message (update session)" + "\r\n" +
											$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
											$"- Type: {message.Type}" + "\r\n" +
											$"- Message: {message.Data.ToString(Formatting.None)}"
										, null, Global.ServiceName, LogLevel.Information, correlatedID).ConfigureAwait(false);
								}

								// revoke a session => tell client to log-out and register new session
								else if (message.Type.IsEquals("Session#Revoke"))
								{
									await session.SendSessionStateAsync(false, correlatedID).ConfigureAwait(false);
									session.SessionID = UtilityService.NewUUID;
									session.User = new User("", session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
									session.Verified = false;
									await Task.WhenAll(
										InternalAPIs.Cache.SetAsync($"Session#{session.SessionID}", session.GetEncryptedID(), 13),
										websocket.SendAsync(new UpdateMessage
										{
											Type = "Users#Session#Revoke",
											Data = session.GetSessionJson()
										})
									).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
											$"Successfully process an inter-communicate message (revoke session)" + "\r\n" +
											$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
											$"- Type: {message.Type}" + "\r\n" +
											$"- Message: {message.Data.ToString(Formatting.None)}"
										, null, Global.ServiceName, LogLevel.Information, correlatedID).ConfigureAwait(false);
								}
							}
							catch (ObjectDisposedException) { }
							catch (Exception ex)
							{
								await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
									$"Error occurred while processing an inter-communicate message => {ex.Message}" + "\r\n" +
									$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
									$"- Type: {message.Type}" + "\r\n" +
									$"- Message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
								, ex, Global.ServiceName, LogLevel.Information, correlatedID).ConfigureAwait(false);
							}
					},
					async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// update the state
			websocket.Set("State", headers.ContainsKey("x-app-token") ? "Verified" : "Connected");
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Visits", $"The real-time updater (RTU) of a subscriber's device is started" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- State: {websocket.Get<string>("State")}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
		}

		static async Task WhenConnectionIsBrokenAsync(this ManagedWebSocket websocket)
		{
			// prepare
			websocket.Set("State", "Disconnected");
			websocket.Remove("Session", out Session session);
			var correlationID = UtilityService.NewUUID;

			// remove the updater
			if (websocket.Remove("Updater", out IDisposable updater))
				try
				{
					updater?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Errors", $"Error occurred while disposing updater: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// remove the communicator
			if (websocket.Remove("Communicator", out IDisposable communicator))
				try
				{
					communicator?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Errors", $"Error occurred while disposing communicator: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// update the session state
			await Task.WhenAll(
				session != null ? session.SendSessionStateAsync(false, correlationID) : Task.CompletedTask,
				Global.IsVisitLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Visits", $"The real-time updater (RTU) of a subscriber's device is stopped" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- Served times: {websocket.Timestamp.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
			).ConfigureAwait(false);
		}

		static async Task WhenMessageIsReceivedAsync(this ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// prepare
			var stopwatch = Stopwatch.StartNew();
			var correlationID = UtilityService.NewUUID;

			// check message
			var requestMsg = result.MessageType.Equals(WebSocketMessageType.Text) ? data.GetString() : null;
			if (string.IsNullOrWhiteSpace(requestMsg))
				return;

			// wait for the initializing process is completed
			while ("Initializing".IsEquals(websocket.Get<string>("State")))
				await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// check session
			var session = websocket.Get<Session>("Session");
			if (session == null)
			{
				await Task.WhenAll(
					Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Errors", $"No session is attached - Request: {requestMsg}", null, Global.ServiceName, LogLevel.Critical, correlationID),
					RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "No session")
				).ConfigureAwait(false);
				return;
			}

			// prepare information
			var requestObj = requestMsg.ToExpandoObject();
			var serviceName = requestObj.Get("ServiceName", "");
			var objectName = requestObj.Get("ObjectName", "");
			var verb = requestObj.Get("Verb", "GET").ToUpper();
			var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			query.TryGetValue("object-identity", out string objectIdentity);
			var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			if (!header.ContainsKey("x-app-token"))
			{
				var token = websocket.Get<JObject>("Token");
				token["iat"] = DateTime.Now.ToUnixTimestamp();
				header["x-app-token"] = JSONWebToken.Encode(token, Global.JWTKey);
			}
			var extra = new Dictionary<string, string>(requestObj.Get("Extra", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);

			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Visits", $"Request starting {verb} " + $"/{serviceName}{(string.IsNullOrWhiteSpace(objectName) ? "" : "/" + objectName)}{(string.IsNullOrWhiteSpace(objectIdentity) ? "" : "/" + objectIdentity)}".ToLower() + (query.TryGetValue("x-request",out string xrequest) ? $"?x-request={xrequest}" : "") + $" HTTPWS/1.1", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);

			// working with sessions
			if ("session".IsEquals(serviceName))
				try
				{
					// verify the session
					if ("VERIFY".IsEquals(verb) || "PATCH".IsEquals(verb))
					{
						websocket.Set("State", "Verifying");
						var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
						var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
						if (!header.TryGetValue("x-session-id", out var sessionID)
							|| !session.SessionID.Equals(session.GetDecryptedID(sessionID.Decrypt(encryptionKey, encryptionIV), Global.EncryptionKey, Global.ValidationKey))
							|| !header.TryGetValue("x-device-id", out var deviceID)
							|| !session.DeviceID.Equals(deviceID.Decrypt(encryptionKey, encryptionIV)))
							throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
						websocket.Set("State", "Verified");
						if (Global.IsDebugLogEnabled)
							await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
								$"Successfully verify the session" + "\r\n" +
								$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
								$"- Request: {requestObj.ToJson().ToString(Formatting.None)}" + "\r\n" +
								$"- Session: {session.ToJson().ToString(Formatting.None)}"
							, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
					}

					// response to a heartbeat => refresh the session
					else if ("PONG".IsEquals(verb) && await websocket.VerifyAsync(session, correlationID).ConfigureAwait(false))
						await Task.WhenAll(
							new CommunicateMessage("Users")
							{
								Type = "Session#State",
								Data = new JObject
								{
									{ "SessionID", session.SessionID },
									{ "UserID", session.User.ID },
									{ "IsOnline", true }
								}
							}.PublishAsync(RTU.Logger, "Http.InternalAPIs"),
							Global.IsDebugLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Successfully send an inter-communicate message to refresh a session when got a response of a heartbeat signal" + "\r\n" + websocket.GetConnectionInfo(session), null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
						).ConfigureAwait(false);

					// unknown
					else
						throw new InvalidRequestException();
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						websocket.SendAsync(ex, null, correlationID),
						Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
							$"Error occurred while processing the session" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- State: {websocket.Get<string>("State")}" + "\r\n" +
							$"- Request: {requestObj.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Session: {session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Error: {ex.Message}"
						, ex, Global.ServiceName, LogLevel.Error, correlationID)
					).ConfigureAwait(false);
					if (ex is InvalidSessionException)
						RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.PolicyViolation, ex.Message);
				}

			// working with services
			else if (await websocket.VerifyAsync(session, correlationID).ConfigureAwait(false))
				try
				{
					// prepare the requesting information
					var body = requestObj.Get("Body");
					var requestInfo = new RequestInfo
					{
						Session = session,
						ServiceName = serviceName,
						ObjectName = objectName,
						Verb = verb,
						Query = query,
						Header = header,
						Body = body == null ? "" : body is string ? body as string : body.ToJson().ToString(Formatting.None),
						Extra = extra,
						CorrelationID = correlationID
					};

					// special: working with users
					if (requestInfo.ServiceName.IsEquals("users"))
					{
						// stop process when request to work with users' sessions
						if ("session".IsEquals(requestInfo.ObjectName))
							throw new InvalidRequestException("Please change to use HTTP RESTful for working with users' sessions");

						// prepare related information
						if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
						{
							requestInfo.CaptchaIsValid();
							if ("account".IsEquals(requestInfo.ObjectName) || "otp".IsEquals(requestInfo.ObjectName))
								requestInfo.PrepareAccountRelated(null, (msg, ex) => Global.WriteLogs(RTU.Logger, "Http.InternalAPIs", msg, ex, Global.ServiceName, LogLevel.Error, correlationID));
						}
						else if ("otp".IsEquals(requestInfo.ObjectName) && requestInfo.Verb.IsEquals("DELETE"))
							requestInfo.PrepareAccountRelated(null, (msg, ex) => Global.WriteLogs(RTU.Logger, "Http.InternalAPIs", msg, ex, Global.ServiceName, LogLevel.Error, correlationID));

						// prepare signature
						requestInfo.Extra["Signature"] = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
							? requestInfo.Body.GetHMACSHA256(Global.ValidationKey)
							: requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
					}

					// special: working with files
					else if (requestInfo.ServiceName.IsEquals("files"))
					{
						requestInfo.Extra["Signature"] = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
							? requestInfo.Body.GetHMACSHA256(Global.ValidationKey)
							: requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
						requestInfo.Extra["SessionID"] = requestInfo.Session.SessionID.GetHMACBLAKE256(Global.ValidationKey);
					}

					// call the service
					var response = Global.StaticSegments.Contains(requestInfo.ServiceName.ToLower())
						? verb.IsEquals("GET")
							? (await Global.GetStaticFileContentAsync(Global.GetStaticFilePath(new[] { requestInfo.ServiceName.ToLower(), requestInfo.ObjectName.ToLower(), objectIdentity })).ConfigureAwait(false)).GetString().ToJson()
							: throw new MethodNotAllowedException(verb)
						: requestInfo.ServiceName.IsEquals("discovery")
							? requestInfo.ObjectName.IsEquals("controllers")
								? InternalAPIs.GetControllers()
								: requestInfo.ObjectName.IsEquals("services")
									? InternalAPIs.GetServices()
									: requestInfo.ObjectName.IsEquals("definitions")
										? await Global.CallServiceAsync(requestInfo.PrepareDefinitionRelated(), Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false)
										: throw new InvalidRequestException("Unknown request")
							: await Global.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);

					// send the response as an update message
					await websocket.SendAsync(new UpdateMessage
					{
						Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + (!string.IsNullOrWhiteSpace(objectIdentity) && !objectIdentity.IsValidUUID() ? objectIdentity : verb).GetCapitalizedFirstLetter()),
						Data = response
					}, requestObj.Get<string>("ID")).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await websocket.SendAsync(ex, null, correlationID, requestObj.Get<string>("ID"), $"Request: {requestObj.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
				}

			stopwatch.Stop();
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Visits", $"Request finished in {stopwatch.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
		}

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string msg = null, string correlationID = null, string identity = null, string additionalMsg = null, string objectName = null)
		{
			// prepare
			correlationID = correlationID ?? UtilityService.NewUUID;
			var wampException = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? wampException?.Item2 ?? exception.Message;
			var type = wampException?.Item3 ?? exception?.GetType().GetTypeName(true);
			var code = wampException != null ? wampException.Item1 : exception.GetHttpStatusCode();

			var message = new JObject
			{
				{ "Message", msg },
				{ "Type", type },
				{ "Code", code },
				{ "CorrelationID", correlationID }
			};

			if (Global.IsDebugStacksEnabled)
			{
				if (wampException != null)
					message["Stack"] = wampException.Item4;

				else
				{
					message["Stack"] = exception.StackTrace;
					if (exception.InnerException != null)
					{
						var inners = new JArray();
						var counter = 1;
						var inner = exception.InnerException;
						while (inner != null)
						{
							inners.Add(new JObject
							{
								{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
								{ "Stack", inner.StackTrace }
							});
							counter++;
							inner = inner.InnerException;
						}
						message["Inners"] = inners;
					}
				}
			}

			// send & write logs
			message = new JObject
			{
				{ "Type", "Error" },
				{ "Data", message }
			};
			if (!string.IsNullOrWhiteSpace(identity))
				message["ID"] = identity;

			await Task.WhenAll(
				websocket.SendAsync(message.ToString(Formatting.None), true, Global.CancellationTokenSource.Token),
				Global.WriteLogsAsync(RTU.Logger, objectName ?? "Http.InternalAPIs", $"{msg ?? exception.Message}", exception, Global.ServiceName, LogLevel.Error, correlationID, string.IsNullOrWhiteSpace(additionalMsg) ? null : $"{additionalMsg}\r\nWebSocket Info:\r\n{websocket.GetConnectionInfo()}")
			).ConfigureAwait(false);
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message, string identity = null)
			=> websocket.SendAsync(message.ToJson(json =>
			{
				(json as JObject).Remove("DeviceID");
				(json as JObject).Remove("ExcludedDeviceID");
				if (!string.IsNullOrWhiteSpace(identity))
					json["ID"] = identity;
			}).ToString(Formatting.None), true, Global.CancellationTokenSource.Token);

		static async Task<bool> VerifyAsync(this ManagedWebSocket websocket, Session session = null, string correlationID = null)
		{
			if (!"Verified".IsEquals(websocket.Get<string>("State")))
			{
				// wait for the verifying process in 5 seconds
				using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
				{
					while (!cts.IsCancellationRequested)
						try
						{
							await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationTokenSource.Token).ConfigureAwait(false);
							if ("Verified".IsEquals(websocket.Get<string>("State")))
								cts.Cancel();
						}
						catch { }
				}
				if (!"Verified".IsEquals(websocket.Get<string>("State")))
				{
					await Task.WhenAll(
						Global.WriteLogsAsync(RTU.Logger, "Http.WebSockets.Errors",
							$"Session is not verified" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- State: {websocket.Get<string>("State")}"
						, null, Global.ServiceName, LogLevel.Critical, correlationID),
						RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "Need to verify the session")
					).ConfigureAwait(false);
					return false;
				}
			}
			return true;
		}

		static async Task PrepareConnectionInfoAsync(this ManagedWebSocket websocket, string correlationID = null, Session session = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			var account = "Visitor";
			if (!string.IsNullOrWhiteSpace(session?.User?.ID))
				try
				{
					var json = await Global.CallServiceAsync(new RequestInfo(session, "Users", "Profile", "GET"), Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);
					account = (json?.Get<string>("Name") ?? "Unknown") + $" ({session.User.ID})";
				}
				catch (Exception ex)
				{
					account = $"Unknown ({session.User.ID})";
					await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an account profile => {ex.Message}", ex).ConfigureAwait(false);
				}
			websocket.Set("AccountInfo", account);
			websocket.Set("LocationInfo", session != null ? await session.GetLocationAsync(correlationID, Global.CancellationTokenSource.Token).ConfigureAwait(false) : "Unknown");
		}

		static string GetConnectionInfo(this ManagedWebSocket websocket, Session session = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			return $"- Account: {websocket.Get("AccountInfo", "Visitor")} - Session ID: {session?.SessionID ?? "Unknown"} - Device ID: {session?.DeviceID ?? "Unknown"} - Origin: {(websocket.Headers.TryGetValue("Origin", out string origin) ? origin : session?.AppOrigin ?? "Unknown")}" + "\r\n" +
				$"- App: {session?.AppName ?? "Unknown"} @ {session?.AppPlatform ?? "Unknown"} [{session?.AppAgent ?? "Unknown"}]" + "\r\n" +
				$"- Connection IP: {session?.IP ?? "Unknown"} - Location: {websocket.Get("LocationInfo", "Unknown")} - WebSocket: {websocket.ID} @ {websocket.RemoteEndPoint}";
		}
	}
}
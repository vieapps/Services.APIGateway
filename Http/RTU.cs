#region Related components
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Dynamic;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.WebSockets;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{
		internal static Components.WebSockets.WebSocket WebSocket { get; private set; }

		internal static ILogger Logger { get; set; }

		internal static void Initialize()
		{
			RTU.WebSocket = new Components.WebSockets.WebSocket(Components.Utility.Logger.GetLoggerFactory(), Global.CancellationTokenSource.Token)
			{
				OnError = (websocket, exception) => Global.WriteLogs(RTU.Logger, "RTU", $"Got error while processing: {exception.Message} ({websocket?.ID} {websocket?.RemoteEndPoint})", exception),
				OnConnectionEstablished = (websocket) => Task.Run(() => RTU.WhenConnectionIsEstablishedAsync(websocket)).ConfigureAwait(false),
				OnConnectionBroken = (websocket) => Task.Run(() => RTU.WhenConnectionIsBrokenAsync(websocket)).ConfigureAwait(false),
				OnMessageReceived = (websocket, result, data) => Task.Run(() => RTU.WhenMessageIsReceivedAsync(websocket, result, data)).ConfigureAwait(false)
			};
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is initialized - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes - Keep-Alive interval: {RTU.WebSocket.KeepAliveInterval.TotalSeconds} second(s)");
		}

		internal static void Dispose()
		{
			RTU.WebSocket.Dispose();
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is stopped");
		}

		static async Task WhenConnectionIsEstablishedAsync(ManagedWebSocket websocket)
		{
			// prepare
			Session session = null;
			Dictionary<string, string> queryString = null;
			try
			{
				queryString = websocket.RequestUri.ParseQuery();

				if (!queryString.ContainsKey("x-request"))
					throw new InvalidRequestException("\"x-request\" is not found");

				ExpandoObject request;
				try
				{
					request = queryString["x-request"].Url64Decode().ToExpandoObject();
				}
				catch (Exception ex)
				{
					throw new InvalidRequestException($"Request is invalid ({ex.Message})", ex);
				}

				var appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
					throw new TokenNotFoundException("Token is not found");

				websocket.Extra.TryGetValue("User-Agent", out object userAgent);
				websocket.Extra.TryGetValue("Referrer", out object urlReferrer);
				var ipAddress = $"{(websocket.RemoteEndPoint as IPEndPoint).Address}";

				session = Global.GetSession(queryString.ToNameValueCollection(), userAgent as string, ipAddress, new Uri(urlReferrer as string));
				session.DeviceID = request.Get("x-device-id", session.DeviceID);
				session.AppName = request.Get("x-app-name", session.AppName);
				session.AppPlatform = request.Get("x-app-platform", session.AppPlatform);

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				await Global.UpdateWithAuthenticateTokenAsync(session, appToken).ConfigureAwait(false);
				if (!await Global.IsSessionExistAsync(session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(RTU.Logger, "RTU", ex.Message, ex).ConfigureAwait(false);

				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException || ex is InvalidRequestException)
					await websocket.SendAsync(ex).ConfigureAwait(false);
				else
					await websocket.SendAsync(new InvalidRequestException($"Request is invalid ({ex.Message})", ex)).ConfigureAwait(false);
				RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InvalidPayloadData, $"Request is invalid ({ex.Message})");
				return;
			}

			// wait for few times before connecting to WAMP router because Reactive.NET needs
			if (queryString.ContainsKey("x-restart"))
			{
				// send knock message
				await websocket.SendAsync(new UpdateMessage { Type = "Knock" }).ConfigureAwait(false);

				// wait for a few times
				try
				{
					await Task.Delay(567, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InternalServerError);
					return;
				}
			}

			// subscribe to push messages
			websocket.Extra["Session"] = session;
			websocket.Extra["Updater"] = WAMPConnections.IncommingChannel.RealmProxy.Services
				.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
				.Subscribe(
					async (message) =>
					{
						if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
							try
							{
								await websocket.SendAsync(message).ConfigureAwait(false);
								if (Global.IsDebugResultsEnabled)
									await Global.WriteLogsAsync(RTU.Logger, "RTU",
										$"Push the message to the subscriber's device successful (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
										$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
										$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
										$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
										$"- Message: {message.Data.ToString(Formatting.Indented)}"
									).ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								await Global.WriteLogsAsync(RTU.Logger, "RTU", 
									$"Pushing error: {ex.Message}" + "\r\n" +
									$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}" + "\r\n" +
									$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
									$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
									$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
									$"- Message: {message.ToJson().ToString(Formatting.None)}"
								, ex).ConfigureAwait(false);
							}
					},
					exception => Global.WriteLogs(RTU.Logger, "RTU", $"Error occurred while fetching messages: {exception.Message}", exception)
				);

			// register online session
			await Task.WhenAll(
				session.SendOnlineStatusAsync(true),
				!Global.IsDebugLogEnabled ? Task.CompletedTask : Global.WriteLogsAsync(RTU.Logger, "RTU",
					$"The real-time updater of a client's device is started (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
					$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
					$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
					$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}"
				)
			).ConfigureAwait(false);
		}

		static async Task WhenConnectionIsBrokenAsync(ManagedWebSocket websocket)
		{
			// prepare
			websocket.Extra.TryGetValue("Session", out object wsession);
			websocket.Extra.TryGetValue("Updater", out object updater);

			if (wsession == null || updater == null)
			{
				await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Connection is closed without attached information (Close status: {websocket?.CloseStatus} - Description: {websocket?.CloseStatusDescription})");
				if (updater != null)
					try
					{
						(updater as IDisposable).Dispose();
					}
					catch { }
				return;
			}

			var session = wsession as Session;
			if (updater != null)
				try
				{
					(updater as IDisposable).Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Error occurred while disposing updater: {session?.ToJson().ToString(Formatting.None)}", ex).ConfigureAwait(false);
				}

			// update online status
			if (session != null)
				await Task.WhenAll(
					session.SendOnlineStatusAsync(false),
					!Global.IsDebugLogEnabled ? Task.CompletedTask : Global.WriteLogsAsync(RTU.Logger, "RTU",
						$"The real-time updater of a client's device is stopped (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
						$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
						$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}"
					)
				).ConfigureAwait(false);
		}

		static async Task WhenMessageIsReceivedAsync(ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// check message
			var requestMsg = result.MessageType.Equals(WebSocketMessageType.Text) ? data.GetString() : null;
			if (string.IsNullOrWhiteSpace(requestMsg))
				return;

			// check session
			websocket.Extra.TryGetValue("Session", out object wsession);
			if (!(wsession is Session session))
			{
				await Global.WriteLogsAsync(RTU.Logger, "RTU", new List<string>
				{
					$"No session is attached to this WebSocket ({websocket.ID} {websocket.RemoteEndPoint})",
					$"Extra information: {wsession?.ToJson().ToString(Formatting.Indented)}"
				}, null, Global.ServiceName, LogLevel.Critical).ConfigureAwait(false);
				RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.Empty, "To restart");
				return;
			}

			// prepare information
			var requestInfo = requestMsg.ToExpandoObject();
			var serviceName = requestInfo.Get<string>("ServiceName");
			var objectName = requestInfo.Get<string>("ObjectName");
			var verb = (requestInfo.Get<string>("Verb") ?? "GET").ToUpper();
			var extra = requestInfo.Get<Dictionary<string, string>>("Extra") ?? new Dictionary<string, string>();

			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Begin process => {verb} /{serviceName}/{objectName}").ConfigureAwait(false);

			// refresh the session
			if ("PING".IsEquals(verb))
				await Task.WhenAll(
					websocket.SendAsync(new UpdateMessage
					{
						Type = "Pong",
						DeviceID = session.DeviceID
					}),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : Global.WriteLogsAsync(RTU.Logger, "RTU",
						$"End process => Successfully refresh (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
						$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
						$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}"
					)
				).ConfigureAwait(false);

			// update the session
			else if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra.ContainsKey("x-session"))
			{
				// call user service
				var sessionID = extra["x-session"].GetDecryptedID();
				var request = new RequestInfo
				{
					Session = new Session(session)
					{
						SessionID = sessionID,
						User = new User(session.User)
						{
							SessionID = sessionID
						}
					},
					ServiceName = "Users",
					ObjectName = "Session",
					Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "x-app-token", $"x-session-token-{sessionID}" }
					},
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", $"x-session-token-{sessionID}".GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = Global.GetCorrelationID()
				};
				var json = await Global.CallServiceAsync(request, Global.CancellationTokenSource.Token, RTU.Logger).ConfigureAwait(false);

				// check results
				if (json == null)
				{
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Failed to patch when got no returing information (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
							$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}"
						).ConfigureAwait(false);
					return;
				}

				// only patch when not expired
				var sessionInfo = json.ToExpandoObject();
				if (DateTime.Parse(sessionInfo.Get<string>("ExpiredAt")) >= DateTime.Now)
				{
					session.SessionID = sessionInfo.Get<string>("ID");
					session.User.ID = sessionInfo.Get<string>("UserID");

					if (session.User.Equals(""))
						session.User = new User("", session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
					else
						session.User = sessionInfo.Get<string>("AccessToken").ParseAccessToken(Global.ECCKey);

					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Successfully patch the session (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
							$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
							$"- Response: {session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						).ConfigureAwait(false);
				}
				else if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(RTU.Logger, "RTU",
						$"End process => Failed to patch because the session is expired (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
						$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
						$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
						$"- Response: {session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
					).ConfigureAwait(false);
			}

			// create new session (anonymous only)
			else if ("NEW".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra.ContainsKey("x-session") && session.User.ID.Equals(""))
			{
				// prepare request
				var sessionID = extra["x-session"].GetDecryptedID();
				var request = new RequestInfo
				{
					Session = new Session(session)
					{
						SessionID = sessionID,
						User = new User("", sessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>())
					},
					ServiceName = "Users",
					ObjectName = "Session",
					Verb = "POST",
					Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
					CorrelationID = Global.GetCorrelationID()
				};

				request.Body = request.GenerateSessionJson().ToString(Formatting.None);
				request.Extra["Signature"] = request.Body.GetHMACSHA256(Global.ValidationKey);

				// call user service
				var json = await Global.CallServiceAsync(request, Global.CancellationTokenSource.Token, RTU.Logger).ConfigureAwait(false);

				// check results
				if (json == null)
				{
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Failed to renew session when got no returing information" + "\r\n" +
							$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}"
						).ConfigureAwait(false);
					return;
				}

				// assign new information
				session.SessionID = json.ToExpandoObject().Get<string>("ID");
				session.User = new User("", session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());

				// send update message
				json = new JObject
				{
					{ "ID", session.SessionID },
					{ "DeviceID", session.DeviceID }
				};
				session.UpdateSessionJson(json, Global.CurrentHttpContext?.Items);

				await websocket.SendAsync(new UpdateMessage
				{
					Type = "Users#Session#Update",
					DeviceID = session.DeviceID,
					Data = json
				}).ConfigureAwait(false);

				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(RTU.Logger, "RTU",
						$"End process => Successfully renew session" + "\r\n" +
						$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
						$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
						$"- Response: {json.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
					).ConfigureAwait(false);
			}

			// call service to process the request
			else if (!string.IsNullOrWhiteSpace(serviceName))
			{
				var stopwatch = Stopwatch.StartNew();
				try
				{
					// call the requested service
					var request = new RequestInfo
					{
						Session = session,
						ServiceName = serviceName,
						ObjectName = objectName,
						Verb = verb,
						Query = requestInfo.Get<Dictionary<string, string>>("Query") ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
						Header = requestInfo.Get<Dictionary<string, string>>("Header") ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
						Body = requestInfo.Get<string>("Body") ?? "",
						Extra = new Dictionary<string, string>(extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
						CorrelationID = Global.GetCorrelationID()
					};

					if (serviceName.IsEquals("Users"))
					{
						if (verb.IsEquals("POST") || verb.IsEquals("PUT"))
							request.Extra["Signature"] = request.Body.GetHMACSHA256(Global.ValidationKey);
						else
						{
							if (!request.Header.ContainsKey("x-app-token"))
								request.Header["x-app-token"] = session.User.GetAuthenticateToken(Global.EncryptionKey, Global.JWTKey);
							request.Extra["Signature"] = request.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
						}
					}

					var json = await Global.CallServiceAsync(request, Global.CancellationTokenSource.Token, RTU.Logger).ConfigureAwait(false);

					// send the update message
					var @event = request.GetObjectIdentity();
					@event = !string.IsNullOrWhiteSpace(@event) && !@event.IsValidUUID()
						? @event
						: verb;
					await websocket.SendAsync(new UpdateMessage
					{
						Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + @event.GetCapitalizedFirstLetter()),
						DeviceID = session.DeviceID,
						Data = json
					}).ConfigureAwait(false);

					stopwatch.Stop();
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Success (Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)})" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
							$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
							$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response: {json.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					stopwatch.Stop();
					await Task.WhenAll(
						websocket.SendAsync(ex),
						Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Error occurred: {ex.Message}" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
							$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}" + "\r\n" +
							$"- Session Info: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Connection Info: {websocket.ID} @ {websocket.RemoteEndPoint}" + "\r\n" +
							$"- Request: {requestInfo?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						, ex)
					).ConfigureAwait(false);
				}
			}
		}

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string msg = null)
		{
			// prepare
			var wampError = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? (wampError != null ? wampError.Item2 : exception.Message);
			var type = wampError != null ? wampError.Item3 : exception.GetType().GetTypeName(true);
			var code = wampError != null ? wampError.Item1 : exception.GetHttpStatusCode();

			var message = new JObject
			{
				{ "Message", msg },
				{ "Type", type },
				{ "Code", code },
				{ "CorrelationID", Global.GetCorrelationID() }
			};

			if (Global.IsDebugStacksEnabled)
			{
				if (wampError != null)
					message["Stack"] = wampError.Item4;

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

			message = new JObject
			{
				{ "Type", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
				websocket.SendAsync(message.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None), true, Global.CancellationTokenSource.Token),
				Global.WriteLogsAsync(RTU.Logger, "RTU", msg ?? $"Error with real-time updater: {exception.Message}", exception)
			).ConfigureAwait(false);
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message)
			=> websocket.SendAsync(message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None), true, Global.CancellationTokenSource.Token);
	}
}
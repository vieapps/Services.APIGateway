#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Web.WebSockets;
using System.Net.WebSockets;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{

		#region Helpers
		internal static ConcurrentDictionary<string, IDisposable> Updaters = new ConcurrentDictionary<string, IDisposable>();
		internal static int _ProcessInterval = 0;

		internal static int ProcessInterval
		{
			get
			{
				if (RTU._ProcessInterval < 1)
					try
					{
						RTU._ProcessInterval = UtilityService.GetAppSetting("RTU:ProcessInterval", "13").CastAs<int>();
					}
					catch
					{
						RTU._ProcessInterval = 13;
					}
				return RTU._ProcessInterval;
			}
		}

		static async Task SendAsync(this AspNetWebSocketContext context, Exception exception, string correlationID = null, string msg = null)
		{
			// prepare
			correlationID = correlationID ?? Base.AspNet.Global.GetCorrelationID(context.Items);

			var wampError = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? (wampError != null
				? wampError.Item2
				: exception.Message);

			var type = wampError != null
				? wampError.Item3
				: exception.GetType().GetTypeName(true);

			var message = new JObject()
			{
				{ "Message", type },
				{ "Type", type },
				{ "CorrelationID", correlationID }
			};

			if (Global.IsShowErrorStacks)
			{
				if (wampError != null)
					message.Add(new JProperty("Stack", wampError.Item4));

				else
				{
					message.Add(new JProperty("Stack", exception.StackTrace));
					if (exception.InnerException != null)
					{
						var inners = new JArray();
						var counter = 1;
						var inner = exception.InnerException;
						while (inner != null)
						{
							inners.Add(new JObject()
							{
								{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
								{ "Stack", inner.StackTrace }
							});
							counter++;
							inner = inner.InnerException;
						}
						message.Add(new JProperty("Inners", inners));
					}
				}
			}

			message = new JObject()
			{
				{ "Type", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
				context.SendAsync(message.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)),
				Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", msg ?? "Error occurred while processing with real-time updater", exception)
			).ConfigureAwait(false);
		}

		static async Task SendAsync(this AspNetWebSocketContext context, string message, string correlationID = null)
		{
			correlationID = correlationID ?? Base.AspNet.Global.GetCorrelationID(context.Items);
			if (context.WebSocket.State.Equals(WebSocketState.Open))
				try
				{
					await context.WebSocket.SendAsync(new ArraySegment<byte>(message.ToBytes()), WebSocketMessageType.Text, true, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Error occurred while sending message via WebSocket [{message}]", ex),
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Error occurred while sending message via WebSocket [{message}]", ex)
					).ConfigureAwait(false);
				}
		}

		static async Task SendAsync(this AspNetWebSocketContext context, UpdateMessage message, string correlationID = null)
		{
			// update into queue
			(context.Items["Messages"] as Queue<UpdateMessage>).Enqueue(message);

			// stop if a send operation is already in progress
			if (context.Items.Contains("Sending"))
				return;

			// send messages
			context.Items.Add("Sending", "");
			while ((context.Items["Messages"] as Queue<UpdateMessage>).Count > 0)
			{
				var msg = (context.Items["Messages"] as Queue<UpdateMessage>).Dequeue();
				await context.SendAsync(msg.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None), correlationID).ConfigureAwait(false);
			}
			context.Items.Remove("Sending");
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
			Session session = null;
			try
			{
				// get app token
				var request = context.QueryString["x-request"]?.Url64Decode().ToExpandoObject() ?? new ExpandoObject();
				var appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
				{
					await context.SendAsync(new TokenNotFoundException("Token is not found")).ConfigureAwait(false);
					return;
				}

				// prepare session
				session = Base.AspNet.Global.GetSession(context.Headers, context.QueryString, context.UserAgent, context.UserHostAddress, context.UrlReferrer);
				session.DeviceID = request.Get("x-device-id", session.DeviceID);
				session.AppName = request.Get("x-app-name", session.AppName);
				session.AppPlatform = request.Get("x-app-platform", session.AppPlatform);

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				var accessToken = session.ParseJSONWebToken(appToken);
				if (!await InternalAPIs.CheckSessionExistAsync(session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				await InternalAPIs.VerifySessionIntegrityAsync(session, accessToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while preparing token of RTU", ex).ConfigureAwait(false);
				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException)
					await context.SendAsync(ex).ConfigureAwait(false);
				else
					await context.SendAsync(new InvalidTokenException("The token is invalid", ex)).ConfigureAwait(false);
				return;
			}

			// queue of messages
			context.Items["Messages"] = new Queue<UpdateMessage>();

			// wait for few times before connecting to WAMP router because Reactive.NET needs few times
			if (context.QueryString["x-restart"] != null)
			{
				// send knock message
				await context.SendAsync(new UpdateMessage()
				{
					Type = "Knock"
				}, correlationID).ConfigureAwait(false);

				// wait for a few times
				try
				{
					await Task.Delay(567, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					return;
				}
			}

			// register online session
			await Task.WhenAll(
				session.SendOnlineStatusAsync(true),
				Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"The real-time updater of a client's device is started - Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)} - Session: {session.SessionID} @ {session.DeviceID} - App Info: {session.AppName} @ {session.AppPlatform}")
			).ConfigureAwait(false);

#if DEBUG || RTULOGS || REQUESTLOGS
			await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
				"The real-time updater of a client's device is started" + "\r\n" +
				$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}\r\n" +
				$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
				$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
			).ConfigureAwait(false);
#endif

			// push
			RTU.Updaters.TryAdd(
				session.DeviceID,
				Base.AspNet.Global.IncommingChannel.RealmProxy.Services
					.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
					.Subscribe(
						async (message) =>
						{
							var relatedID = UtilityService.NewUUID;
							if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
								try
								{
									await context.SendAsync(message, relatedID).ConfigureAwait(false);
#if DEBUG || RTULOGS
									await Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU",
										"Push the message to the subscriber's device successful" + "\r\n" +
										$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
										$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
										$"- Message:\r\n{message.Data.ToString(Formatting.Indented)}"
									).ConfigureAwait(false);
#endif
								}
								catch (Exception ex)
								{
									await Task.WhenAll(
										Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Error occurred while pushing message to the subscriber's device\r\n{message.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
										Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", $"Error occurred while pushing message to the subscriber's device\r\n{message.ToJson().ToString(Formatting.None)}", ex)
									).ConfigureAwait(false);
								}
						},
						async (exception) =>
						{
							await Task.WhenAll(
								Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while fetching update messages", exception),
								Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while fetching messages", exception)
							).ConfigureAwait(false);
						}
					)
			);

			// process
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						if (RTU.Updaters.TryRemove(session.DeviceID, out IDisposable updater))
							updater.Dispose();
					}
					catch (Exception ex)
					{
						await Task.WhenAll(
							Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Error occurred while disposing updater: {session.ToJson().ToString(Formatting.None)}", ex),
							Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Error occurred while disposing updater: {session.ToJson().ToString(Formatting.None)}", ex)
						).ConfigureAwait(false);
					}

					// update online status
					await Task.WhenAll(
						session.SendOnlineStatusAsync(false),
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"The real-time updater of a client's device is stopped - Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)} - Session: {session.SessionID} @ {session.DeviceID} - App Info: {session.AppName} @ {session.AppPlatform}")
					).ConfigureAwait(false);

#if DEBUG || RTULOGS || REQUESTLOGS
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
						"The real-time updater of a client's device is stopped" + "\r\n" +
						$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}\r\n" +
						$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
					).ConfigureAwait(false);
#endif
					return;
				}

				// receive the request
				var requestMessage = "";
				try
				{
					var buffer = new ArraySegment<byte>(new byte[4096]);
					var message = await context.WebSocket.ReceiveAsync(buffer, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
					requestMessage = message.MessageType.Equals(WebSocketMessageType.Text)
						? buffer.Array.GetString(message.Count)
						: null;
				}
				catch (WebSocketException ex)
				{
					if (ex.Message.IsStartsWith("Reached the end of the file") || ex.Message.IsStartsWith("The I/O operation has been aborted because of either a thread exit or an application request"))
						requestMessage = null;
					else
					{
						await Task.WhenAll(
							Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while processing client message", ex),
							Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing client message", ex)
						).ConfigureAwait(false);
						return;
					}
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while processing client message", ex),
						Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing client message", ex)
					).ConfigureAwait(false);
					return;
				}

				// prepare information
				var requestInfo = requestMessage?.ToExpandoObject() ?? new ExpandoObject();
				var serviceName = requestInfo.Get<string>("ServiceName");
				var objectName = requestInfo.Get<string>("ObjectName");
				var verb = (requestInfo.Get<string>("Verb") ?? "GET").ToUpper();
				var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

#if DEBUG || RTULOGS || PROCESSLOGS
				await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Process request [{verb}]: /{serviceName ?? "unknown"}/{objectName ?? "unknown"}").ConfigureAwait(false);
#endif
				// refresh the session
				if ("PING".IsEquals(verb))
					await context.SendAsync(new UpdateMessage()
					{
						Type = "Pong",
						DeviceID = session.DeviceID
					}, correlationID).ConfigureAwait(false);

				// update the session
				else if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra != null && extra.ContainsKey("x-session"))
				{
					var sessionJson = await InternalAPIs.CallServiceAsync(new RequestInfo()
					{
						Session = new Session(session)
						{
							SessionID = extra["x-session"].Decrypt(Base.AspNet.Global.EncryptionKey.Reverse(), true)
						},
						ServiceName = "Users",
						ObjectName = "Session",
						Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "x-app-token", $"x-token-{extra["x-session"]}" }
						},
						Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "Signature", $"x-token-{extra["x-session"]}".GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
						},
						CorrelationID = correlationID
					}).ConfigureAwait(false);

					var sessionInfo = sessionJson.ToExpandoObject();

					session.SessionID = sessionInfo.Get<string>("ID");
					session.User.ID = sessionInfo.Get<string>("UserID");

					session.User = session.User.ID.Equals("")
						? new User() { Roles = new List<string>() { SystemRole.All.ToString() } }
						: (await InternalAPIs.CallServiceAsync(session, "Users", "Account").ConfigureAwait(false)).FromJson<User>();

					await Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Patch a session successful (via WebSocket){(Base.AspNet.Global.IsDebugResultsEnabled ? "\r\n" + session.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : "")}").ConfigureAwait(false);

#if DEBUG || RTULOGS || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(UtilityService.NewUUID, "RTU", $"Patch a session successful\r\n{session.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
#endif
				}

				// call service to process the request
				else if (!string.IsNullOrWhiteSpace(serviceName))
				{
					var relatedID = UtilityService.NewUUID;
					try
					{
						var stopwatch = new Stopwatch();
						stopwatch.Start();

						var request = new RequestInfo(session, serviceName, objectName, verb, requestInfo.Get<Dictionary<string, string>>("Query"), requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, relatedID);
						if (serviceName.IsEquals("Users"))
							request.Extra["Signature"] = verb.IsEquals("POST") || verb.IsEquals("PUT")
								? request.Body.GetHMACSHA256(Base.AspNet.Global.ValidationKey)
								: (request.Header.ContainsKey("x-app-token") ? request.Header["x-app-token"] : $"x-token-{session.SessionID}").GetHMACSHA256(Base.AspNet.Global.ValidationKey);
						var data = await InternalAPIs.CallServiceAsync(request, "RTU").ConfigureAwait(false);

						// send the update message
						var @event = request.GetObjectIdentity();
						@event = !string.IsNullOrWhiteSpace(@event) && !@event.IsValidUUID()
							? @event
							: verb;
						await context.SendAsync(new UpdateMessage()
						{
							Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + @event.GetCapitalizedFirstLetter()),
							DeviceID = session.DeviceID,
							Data = data
						}, relatedID).ConfigureAwait(false);

						stopwatch.Stop();
						await Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName,
							$"Process the request successful (via WebSocket)" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
							$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP}]" + "\r\n" +
							$"- Request:\r\n{requestInfo.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response:{(Base.AspNet.Global.IsDebugResultsEnabled ? "\r\n" + data.ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : " (Hidden)")}"
						).ConfigureAwait(false);

#if DEBUG || RTULOGS || PROCESSLOGS
						await Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU",
							$"Process the request successful" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
							$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Request:\r\n{requestInfo.ToJson().ToString(Formatting.Indented)}" + "\r\n" +
							$"- Response:\r\n{data.ToString(Formatting.Indented)}"
						).ConfigureAwait(false);
#endif
					}
					catch (Exception ex)
					{
						await Task.WhenAll(
							Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Error occurred while processing client message (via WebSocket): {requestInfo?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
							context.SendAsync(ex, relatedID, $"Error occurred while processing client message: {requestInfo?.ToJson().ToString(Formatting.Indented)}")
						).ConfigureAwait(false);
					}
				}

				// stand for next interval
				try
				{
					await Task.Delay(RTU.ProcessInterval, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					return;
				}
			}
		}
	}
}
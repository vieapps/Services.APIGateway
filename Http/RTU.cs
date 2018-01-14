#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Web.WebSockets;
using System.Net.WebSockets;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{

		#region Helpers
		internal static ISubject<UpdateMessage> Publisher = null;
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

		internal static IDisposable RegisterUpdater(string identity, Action<UpdateMessage> onNext, Action<Exception> onError)
		{
			identity = string.IsNullOrWhiteSpace(identity)
				? UtilityService.GetUUID()
				: identity;

			if (!RTU.Updaters.TryGetValue(identity, out IDisposable updater))
				lock (RTU.Updaters)
				{
					if (!RTU.Updaters.TryGetValue(identity, out updater))
					{
						updater = Base.AspNet.Global.IncommingChannel.RealmProxy.Services
							.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
							.Subscribe(onNext, onError);
						RTU.Updaters.TryAdd(identity, updater);
					}
				}

			return updater;
		}

		internal static void UnregisterUpdater(string identity)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Updaters.ContainsKey(identity))
				try
				{
					RTU.Updaters[identity].Dispose();
					RTU.Updaters.TryRemove(identity, out IDisposable instance);
				}
				catch { }
		}

		internal static void StopUpdaters()
		{
			RTU.Updaters.ForEach(updater =>
			{
				try
				{
					updater.Dispose();
				}
				catch { }
			});
		}

		static async Task SendAsync(this AspNetWebSocketContext context, UpdateMessage message)
		{
			await context.SendAsync(message.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)).ConfigureAwait(false);
		}

		static async Task SendAsync(this AspNetWebSocketContext context, Exception exception)
		{
			// prepare
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
			var message = new JObject()
			{
				{ "Type", exception.GetType().GetTypeName(true) },
				{ "Message", exception.Message },
				{ "CorrelationID", correlationID }
			};

			if (Global.IsShowErrorStacks)
			{
				message.Add(new JProperty("Stack", exception.StackTrace));
				if (exception.InnerException != null)
				{
					var inners = new JArray();
					var counter = 0;
					var inner = exception.InnerException;
					while (inner != null)
					{
						counter++;
						inners.Add(new JObject()
						{
							{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
							{ "Stack", inner.StackTrace }
						});
						inner = inner.InnerException;
					}
					message.Add(new JProperty("Inners", inners));
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
				Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Error occurred while processing with real-time updater: {exception.Message}", exception)
			).ConfigureAwait(false);
		}

		static async Task SendAsync(this AspNetWebSocketContext context, string message)
		{
			if (context.WebSocket.State.Equals(WebSocketState.Open))
				try
				{
					await context.WebSocket.SendAsync(new ArraySegment<byte>(message.ToBytes()), WebSocketMessageType.Text, true, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(Base.AspNet.Global.GetCorrelationID(context.Items), "RTU", $"Error occurred while sending message via WebSocket: {ex.Message}", ex).ConfigureAwait(false);
				}
		}

		internal static void Publish(this UpdateMessage message)
		{
			if (RTU.Publisher == null)
				try
				{
					Task.Run(async () =>
					{
						try
						{
							await Base.AspNet.Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
							RTU.Publisher = Base.AspNet.Global.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
							RTU.Publisher.OnNext(message);
						}
						catch (Exception ex)
						{
							Base.AspNet.Global.WriteLogs(UtilityService.NewUID, "RTU", $"Error occurred while publishing message: {ex.Message}", ex);
						}
					}).ConfigureAwait(false);
				}
				catch { }

			else
				RTU.Publisher.OnNext(message);
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare
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
				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException)
					await context.SendAsync(ex).ConfigureAwait(false);
				else
					await context.SendAsync(new InvalidTokenException("The token is invalid", ex)).ConfigureAwait(false);
				return;
			}

			// wait for few times before connecting to WAMP router because Reactive.NET needs few times
			if (context.QueryString["x-restart"] != null)
			{
				// send knock message
				await context.SendAsync(new UpdateMessage()
				{
					Type = "Knock"
				}).ConfigureAwait(false);

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
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
			await session.SendOnlineStatusAsync(true).ConfigureAwait(false);

#if DEBUG || RTULOGS || REQUESTLOGS
			await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
				"The real-time updater of a client's device is started" + "\r\n" +
				$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}\r\n" +
				$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
				$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
			).ConfigureAwait(false);
#endif

			// push
			RTU.RegisterUpdater(
				session.DeviceID,
				async (message) =>
				{
					if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
						try
						{
							await context.SendAsync(message).ConfigureAwait(false);
#if DEBUG || RTULOGS
							await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
								"Push the message to the subscriber's device successful" + "\r\n" +
								$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
								$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
								$"- Message:\r\n{message.Data.ToString(Formatting.Indented)}"
							).ConfigureAwait(false);
#endif
						}
						catch (Exception ex)
						{
							await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
								"Error occurred while pushing message to the subscriber's device" + "\r\n" +
								"- Message: " + message.ToJson().ToString(Formatting.None)
							, ex).ConfigureAwait(false);
						}
				},
				(ex) =>
				{
					Base.AspNet.Global.WriteLogs(correlationID, "RTU", "Error occurred while fetching messages", ex);
				}
			);

			// process
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						RTU.UnregisterUpdater(session.DeviceID);
					}
					catch (Exception ex)
					{
						await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while disposing updater", ex).ConfigureAwait(false);
					}

					// update online status
					await session.SendOnlineStatusAsync(false).ConfigureAwait(false);

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
						await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing client message", ex).ConfigureAwait(false);
						return;
					}
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing client message", ex).ConfigureAwait(false);
					return;
				}

				// prepare information
				var requestInfo = requestMessage?.ToExpandoObject() ?? new ExpandoObject();
				var serviceName = requestInfo.Get<string>("ServiceName");
				var objectName = requestInfo.Get<string>("ObjectName");
				var verb = (requestInfo.Get<string>("Verb") ?? "GET").ToUpper();
				var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

#if DEBUG || RTULOGS || PROCESSLOGS
				var stopwatch = new Stopwatch();
				stopwatch.Start();
				await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Process request [{verb}]: /{serviceName ?? "unknown"}/{objectName ?? "unknown"}").ConfigureAwait(false);
#endif
				// refresh the session
				if ("PING".IsEquals(verb))
					await context.SendAsync(new UpdateMessage()
					{
						Type = "Pong"
					}).ConfigureAwait(false);

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

#if DEBUG || RTULOGS || PROCESSLOGS
					stopwatch.Stop();
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Patch a session successful{session.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
#endif
				}

				// call service to process the request
				else if (!string.IsNullOrWhiteSpace(serviceName))
				{
					// call the service
					var query = requestInfo.Get<Dictionary<string, string>>("Query");
					var request = new RequestInfo(session, serviceName, objectName, verb, query, requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, correlationID);
					if (serviceName.IsEquals("Users"))
						request.Extra["Signature"] = verb.IsEquals("POST") || verb.IsEquals("PUT")
							? request.Body.GetHMACSHA256(Base.AspNet.Global.ValidationKey)
							: (request.Header.ContainsKey("x-app-token") ? request.Header["x-app-token"] : $"x-token-{session.SessionID}").GetHMACSHA256(Base.AspNet.Global.ValidationKey);
					var data = await InternalAPIs.CallServiceAsync(request, "RTU").ConfigureAwait(false);

					// send the update message
					var objectIdentity = query != null && query.ContainsKey("object-identity") ? query["object-identity"] : null;
					await context.SendAsync(new UpdateMessage()
					{
						Type = serviceName.GetCapitalizedFirstLetter() + "#" + objectName.GetCapitalizedFirstLetter() + (objectIdentity != null && !objectIdentity.IsValidUUID() ? "#" + objectIdentity.GetCapitalizedFirstLetter() : ""),
						DeviceID = session.DeviceID,
						Data = data
					}).ConfigureAwait(false);

#if DEBUG || RTULOGS || PROCESSLOGS
					stopwatch.Stop();
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
						$"Process the request successful" + "\r\n" +
						$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
						$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
						$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
						$"- Request:\r\n{requestInfo.ToJson().ToString(Formatting.Indented)}" + "\r\n" +
						$"- Response:\r\n{data.ToString(Formatting.Indented)}"
					).ConfigureAwait(false);
#endif
				}

				// wait for next interval
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
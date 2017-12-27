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

		#region Attributes
		internal static ISubject<UpdateMessage> Sender = null;
		internal static ConcurrentDictionary<string, IDisposable> Updaters = new ConcurrentDictionary<string, IDisposable>();

		internal static int _PushInterval = 0, _ProcessInterval = 0;

		internal static int PushInterval
		{
			get
			{
				if (RTU._PushInterval < 1)
					try
					{
						RTU._PushInterval = UtilityService.GetAppSetting("RTUPushInterval", "123").CastAs<int>();
					}
					catch
					{
						RTU._PushInterval = 123;
					}
				return RTU._PushInterval;
			}
		}

		internal static int ProcessInterval
		{
			get
			{
				if (RTU._ProcessInterval < 1)
					try
					{
						RTU._ProcessInterval = UtilityService.GetAppSetting("RTUProcessInterval", "13").CastAs<int>();
					}
					catch
					{
						RTU._ProcessInterval = 13;
					}
				return RTU._ProcessInterval;
			}
		}
		#endregion

		#region Updaters
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

		internal static void UnregisterUpdater(string identity, bool remove = true)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Updaters.ContainsKey(identity))
				try
				{
					RTU.Updaters[identity].Dispose();
					if (remove)
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
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare
			Session session = null;
			try
			{
				// get app token
				var request = context.QueryString["x-request"]?.Url64Decode().ToExpandoObject() ?? new ExpandoObject();
				string appToken = request.Get<string>("x-app-token");
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

			// wait for few times before connecting to WAMP router because Reactive.NET needs times
			if (context.QueryString["x-restart"] != null)
				try
				{
					await Task.Delay(567, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					return;
				}

			// do the process
			if (session.SessionID.Encrypt(Base.AspNet.Global.AESKey.Reverse(), true).IsEquals(context.QueryString["x-receiver"]))
				await context.ProcesMessagesAsync(session).ConfigureAwait(false);
			else
				await context.PushMessagesAsync(session).ConfigureAwait(false);
		}

		#region Send messages via web socket
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
		#endregion

		#region Push messages to client devices
		static async Task PushMessagesAsync(this AspNetWebSocketContext context, Session session)
		{
			// fetch messages
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
			var messages = new ConcurrentQueue<UpdateMessage>();
			try
			{
				RTU.RegisterUpdater(
					session.SessionID,
					(message) =>
					{
						messages.Enqueue(message);
#if DEBUG || RTULOGS
						Base.AspNet.Global.WriteLogs(correlationID, "RTU", $"Got an update message: {message.ToJson().ToString(Formatting.None)}");
#endif
					},
					(ex) =>
					{
						Base.AspNet.Global.WriteLogs(correlationID, "RTU", $"Error occurred while fetching messages", ex);
					});
			}
			catch (Exception ex)
			{
				await context.SendAsync(new InvalidAppOperationException("Cannot start the subscriber of updating messages", ex)).ConfigureAwait(false);
				return;
			}

			// send knock message on re-start
			if (context.QueryString["x-restart"] != null)
				try
				{
					await context.SendAsync(new UpdateMessage()
					{
						Type = "Knock"
					}).ConfigureAwait(false);
				}
				catch { }

			// register online session
			await session.SendOnlineStatusAsync(true).ConfigureAwait(false);

#if DEBUG || RTULOGS || REQUESTLOGS
			await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", 
				"The real-time updater of a client's device is started" + "\r\n" +
				$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}\r\n" +
				$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
				$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
			).ConfigureAwait(false);
#endif

			// do push
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						RTU.UnregisterUpdater(session.SessionID);
					}
					catch (Exception ex)
					{
						await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Error occurred while disposing subscriber", ex).ConfigureAwait(false);
					}

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

				// push messages to client's device
				while (messages.TryDequeue(out UpdateMessage message))
					if (message != null && message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
						try
						{
							await context.SendAsync(message).ConfigureAwait(false);

#if DEBUG || RTULOGS
							await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
								"Push the message to the subscriber's device successful" + "\r\n" +
								$"- Session: {session.SessionID} @ {session.DeviceID}\r\n" +
								$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
								$"- Message:\r\n" + message.Data.ToString(Formatting.Indented)
							).ConfigureAwait(false);
#endif
						}
						catch (OperationCanceledException)
						{
							return;
						}
						catch (Exception ex)
						{
							await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU",
								"Error occurred while pushing message to the subscriber's device" + "\r\n" +
								"- Message: " + message.ToJson().ToString(Formatting.None)
							, ex).ConfigureAwait(false);
						}

				// wait for next interval
				try
				{
					await Task.Delay(RTU.PushInterval, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					return;
				}
			}
		}
		#endregion

		#region Process request messages that sent from client devices
		internal static void Publish(this UpdateMessage message)
		{
			if (RTU.Sender == null)
				Task.Run(async () =>
				{
					try
					{
						await Base.AspNet.Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
						RTU.Sender = Base.AspNet.Global.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
						RTU.Sender.OnNext(message);
					}
					catch { }
				}).ConfigureAwait(false);

			else
				RTU.Sender.OnNext(message);
		}

		static async Task ProcesMessagesAsync(this AspNetWebSocketContext context, Session session)
		{
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
					return;

				// prepare the request
				var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
				var requestMessage = "";
				try
				{
					// receive the request
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
							throw ex;
					}
					catch (Exception)
					{
						throw;
					}

					// prepare information
					var requestInfo = requestMessage?.ToExpandoObject() ?? new ExpandoObject();
					var serviceName = requestInfo.Get<string>("ServiceName");
					var objectName = requestInfo.Get<string>("ObjectName");
					var verb = requestInfo.Get<string>("Verb") ?? "GET";
					var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

#if DEBUG || RTULOGS
					var stopwatch = new Stopwatch();
					stopwatch.Start();
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Process request [{verb}]: /{serviceName}/{objectName}").ConfigureAwait(false);
#endif

					// update the session
					if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra != null && extra.ContainsKey("x-session"))
					{
						var sessionInfo = (await InternalAPIs.CallServiceAsync(new Session(session)
						{
							SessionID = extra["x-session"].Decrypt(Base.AspNet.Global.AESKey.Reverse(), true)
						}, "users", "session").ConfigureAwait(false)).ToExpandoObject();

						session.SessionID = sessionInfo.Get<string>("ID");
						session.User.ID = sessionInfo.Get<string>("UserID");

						session.User = session.User.ID.Equals("")
							? new User() { Roles = new List<string>() { SystemRole.All.ToString() } }
							: (await InternalAPIs.CallServiceAsync(session, "users", "account").ConfigureAwait(false)).FromJson<User>();

#if DEBUG || RTULOGS
						stopwatch.Stop();
						await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Patch a session successful" + "\r\n" + session.ToJson().ToString(Formatting.Indented)).ConfigureAwait(false);
#endif
					}

					// call service to process the request
					else
					{
						// call the service
						var query = requestInfo.Get<Dictionary<string, string>>("Query");
						var data = await InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb, query, requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, correlationID), "RTU").ConfigureAwait(false);

						// send the update message
						var objectIdentity = query != null && query.ContainsKey("object-identity") ? query["object-identity"] : null;
						new UpdateMessage()
						{
							Type = serviceName.GetCapitalizedFirstLetter() + "#" + objectName.GetCapitalizedFirstLetter() + (objectIdentity != null && !objectIdentity.IsValidUUID() ? "#" + objectIdentity.GetCapitalizedFirstLetter() : ""),
							DeviceID = session.DeviceID,
							Data = data
						}.Publish();

#if DEBUG || RTULOGS
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
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", new List<string>()
					{
						"Error occurred while processing the client messages",
						"- Session: " + session.SessionID + " @ " + session.DeviceID,
						"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + $" [IP: {session.IP} - Agent: {session.AppAgent}]",
						"- Request: " + requestMessage ?? "None"
					}, ex).ConfigureAwait(false);
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
		#endregion

	}
}
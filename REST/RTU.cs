#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Text;
using System.Dynamic;
using System.Web.WebSockets;
using System.Net.WebSockets;

using System.Reactive.Linq;

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
		internal static Dictionary<string, IDisposable> Updaters = new Dictionary<string, IDisposable>();

		internal static int _WaitingInterval = 0;

		internal static int WaitingInterval
		{
			get
			{
				if (RTU._WaitingInterval < 1)
					try
					{
						RTU._WaitingInterval = UtilityService.GetAppSetting("RTUWaitingInterval", "123").CastAs<int>();
					}
					catch
					{
						RTU._WaitingInterval = 123;
					}
				return RTU._WaitingInterval;
			}
		}
		#endregion

		#region Updaters
		internal static IDisposable RegisterUpdater(string identity, Action<UpdateMessage> onNext, Action<Exception> onError)
		{
			identity = string.IsNullOrWhiteSpace(identity)
				? UtilityService.GetUUID()
				: identity;

			var subject = Global.IncommingChannel?.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
			if (subject == null)
				throw new InvalidAppOperationException("Cannot initialize the subject for fetching messages");

			if (!RTU.Updaters.TryGetValue(identity, out IDisposable updater))
				lock (RTU.Updaters)
				{
					if (!RTU.Updaters.TryGetValue(identity, out updater))
					{
						updater = subject.Subscribe(onNext, onError);
						RTU.Updaters.Add(identity, updater);
					}
				}

			return updater;
		}

		internal static void UnregisterUpdater(string identity, bool remove = true)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Updaters.ContainsKey(identity))
			{
				RTU.Updaters[identity].Dispose();
				if (remove)
					RTU.Updaters.Remove(identity);
			}
		}

		internal static void StopUpdaters()
		{
			RTU.Updaters.ForEach(updater => updater.Dispose());
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare client credential
			ExpandoObject request = null;
			try
			{
				request = context.QueryString["x-request"] != null
					? context.QueryString["x-request"].Url64Decode().ToExpandoObject()
					: new ExpandoObject();
			}
			catch (Exception ex)
			{
				await context.SendAsync(new TokenNotFoundException("Token is not found", ex));
				return;
			}

			string appToken = request.Get<string>("x-app-token");
			if (string.IsNullOrWhiteSpace(appToken))
			{
				await context.SendAsync(new TokenNotFoundException("Token is not found"));
				return;
			}

			var session = Global.GetSession(context.Headers, context.QueryString, context.UserAgent, context.UserHostAddress, context.UrlReferrer);
			if (request.Has("x-device-id"))
				session.DeviceID = request.Get<string>("x-device-id");
			if (request.Has("x-app-name"))
				session.AppName = request.Get<string>("x-app-name");
			if (request.Has("x-app-platform"))
				session.AppPlatform = request.Get<string>("x-app-platform");

			if (string.IsNullOrWhiteSpace(session.DeviceID))
			{
				await context.SendAsync(new InvalidTokenException("Device identity is not found"));
				return;
			}

			// prepare client credential
			try
			{
				var accessToken = session.ParseJSONWebToken(appToken);
				if (!await InternalAPIs.CheckSessionExistAsync(session))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				await InternalAPIs.VerifySessionIntegrityAsync(session, accessToken);
			}
			catch (Exception ex)
			{
				await context.SendAsync(ex);
				return;
			}

			// connect to the router
			try
			{
				await Global.OpenIncomingChannelAsync();
			}
			catch (Exception ex)
			{
				await context.SendAsync(new InvalidAppOperationException("Cannot open the channel of the real-time updater", ex));
				return;
			}

			// wait for few seconds before connecting to WAMP router because Reactive.NET needs few times
			if (context.QueryString["x-restart"] != null)
				await Task.Delay(567);

			// prepare working mode
			var correlationID = Global.GetCorrelationID(context.Items);
			var mode = session.SessionID.Encrypt(Global.AESKey.Reverse(), true).IsEquals(context.QueryString["x-mode"])
				? "Sender"
				: "Receiver";

			// fetch messages
			Queue<UpdateMessage> messages = null;
			if (mode.IsEquals("Receiver"))
			{
				messages = new Queue<UpdateMessage>();
				try
				{
					RTU.RegisterUpdater(
						session.SessionID,
						(message) =>
						{
							messages.Enqueue(message);
#if DEBUG || RTULOGS
							Global.WriteLogs(correlationID, "RTU", "Got an update message: " + message.ToJson().ToString(Formatting.None));
#endif
						},
						(ex) =>
						{
							Global.WriteLogs(correlationID, "RTU", "Error occurred while fetching messages", ex);
						});

#if DEBUG || RTULOGS
					Global.WriteLogs(correlationID, "RTU", new List<string>() {
						"The real-time updater of a client's device is started",
						"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
						"- Session: " + session.SessionID + " @ " + session.DeviceID,
						"- Info: " + session.AppName + " / " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
					});
#endif
				}
				catch (Exception ex)
				{
					await context.SendAsync(new InvalidAppOperationException("Cannot start the subscriber of updating messages", ex));
					return;
				}

				// ping message on re-start
				if (context.QueryString["x-restart"] != null)
					try
					{
						await context.SendAsync(new UpdateMessage() { Type = "Ping", DeviceID = session.DeviceID });
					}
					catch { }

				// register online session
				await session.SendOnlineStatusAsync(true);
			}

			// do the process
			while (true)
			{
				// client is disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					if (mode.IsEquals("Receiver"))
					{
						try
						{
							RTU.UnregisterUpdater(session.SessionID);
						}
						catch (Exception ex)
						{
							Global.WriteLogs(correlationID, "RTU", "Error occurred while disposing subscriber: " + ex.Message, ex);
						}

						await session.SendOnlineStatusAsync(false);

#if DEBUG || RTULOGS
						await Global.WriteLogsAsync(correlationID, "RTU", new List<string>() {
							"The real-time updater of a client's device is stopped",
							"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
							"- Session: " + session.SessionID + " @ " + session.DeviceID,
							"- Info: " + session.AppName + " / " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
						});
#endif
					}

					// drop the connection
					break;
				}

				// push messages to client's device
				if (mode.IsEquals("Receiver"))
					while (messages.Count > 0)
						try
						{
							var message = messages.Dequeue();
							if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
							{
								await context.SendAsync(message);
#if DEBUG || RTULOGS
								await Global.WriteLogsAsync(correlationID, "RTU", new List<string>() {
									"Push the message to the subscriber's device successful",
									"- Session: " + session.SessionID,
									"- Device: " + session.DeviceID + " @ " + session.AppName + " / " + session.AppPlatform + " [IP: " + session.IP + "]",
									"- Message: " + message.Data.ToString(Formatting.None)
								});
#endif
							}
						}
						catch (Exception ex)
						{
							Global.WriteLogs(correlationID, "RTU", "Error occurred while pushing message to the subscriber's device", ex);
						}

				// process the request of a service
				else
					await context.ProcessClientRequestAsync(session);

				// wait for next interval
				try
				{
					await Task.Delay(RTU.WaitingInterval, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException)
				{
					break;
				}
				catch (Exception) { }
			}
		}

		#region Send messages
		static async Task SendAsync(this AspNetWebSocketContext context, UpdateMessage message)
		{
			// prepare the message
			var json = message.ToJson() as JObject;
			json.Add(new JProperty("Status", "OK"));

			// send the message
			await context.SendAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
		}

		static async Task SendAsync(this AspNetWebSocketContext context, Exception exception)
		{
			// prepare
			var correlationID = Global.GetCorrelationID(context.Items);
			var message = new JObject()
			{
				{ "Message", exception.Message },
				{ "CorrelationID", correlationID },
				{ "Type", exception.GetType().ToString().ToArray('.').Last() },
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
				{ "Status", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
					context.SendAsync(message.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)),
					Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing with real-time updater: " + exception.Message, exception)
				);
		}

		static async Task SendAsync(this AspNetWebSocketContext context, string message)
		{
			if (context.WebSocket.State.Equals(WebSocketState.Open))
				try
				{
					await context.WebSocket.SendAsync(new ArraySegment<byte>(message.ToBytes()), WebSocketMessageType.Text, true, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(Global.GetCorrelationID(context.Items), "RTU", "Error occurred while sending message via WebSocket: " + ex.Message, ex);
				}
		}
		#endregion

		#region Receive request & call services
		static async Task ProcessClientRequestAsync(this AspNetWebSocketContext context, Session session)
		{
			var correlationID = UtilityService.GetUUID();
			try
			{
				// receive message from client
				var buffer = new ArraySegment<byte>(new byte[2048]);
				var message = await context.WebSocket.ReceiveAsync(buffer, Global.CancellationTokenSource.Token);

				if (!message.MessageType.Equals(WebSocketMessageType.Text))
					return;

				// parse request and process
				var requestInfo = buffer.Array.GetString(message.Count).ToExpandoObject();
				if (requestInfo != null)
				{
					var serviceName = requestInfo.Get<string>("ServiceName");
					var objectName = requestInfo.Get<string>("ObjectName");
					var verb = requestInfo.Get<string>("Verb") ?? "GET";
					var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

					// update the session
					if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra != null && extra.ContainsKey("x-rtu-session"))
						await session.PatchAsync(extra["x-rtu-session"], correlationID);

					// call service to update
					else
					{
						// call the service
						var query = requestInfo.Get<Dictionary<string, string>>("Query");
						var data = await InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb, query, requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, correlationID));

						// prepare the update message
						var objectIdentity = query != null && query.ContainsKey("object-identity")
							? query["object-identity"]
							: null;
						var updateMessage = new UpdateMessage()
						{
							Type = serviceName.GetCapitalizedFirstLetter() + "#" + objectName.GetCapitalizedFirstLetter() + (objectIdentity != null && !objectIdentity.IsValidUUID() ? "#" + objectIdentity.GetCapitalizedFirstLetter() : ""),
							DeviceID = session.DeviceID,
							Data = data
						};

						// publish the update message
						await Global.OpenOutgoingChannelAsync();
						var subject = Global.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
						subject.OnNext(updateMessage);

#if DEBUG || RTULOGS
						await Global.WriteLogsAsync(correlationID, "RTU", new List<string>() {
							"Receive the request and process successful",
							"- Session: " + session.SessionID,
							"- Device: " + session.DeviceID + " @ " + session.AppName + " / " + session.AppPlatform + " [IP: " + session.IP + "]",
							"- Request: " + buffer.Array.GetString(message.Count),
							"- Result: " + data.ToString(Formatting.None)
						});
#endif
					}
				}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing the request of a service with real-time updater: " + ex.Message, ex);
			}
		}

		static async Task PatchAsync(this Session session, string sessionID, string correlationID)
		{
			try
			{
#if DEBUG
				Global.WriteLogs(correlationID, "RTU", "Patch a session [" + sessionID + "]");
#endif

				var info = (await InternalAPIs.CallServiceAsync(new Session(session)
				{
					SessionID = sessionID.Decrypt(Global.AESKey.Reverse(), true)
				}, "users", "session")).ToExpandoObject();

				session.SessionID = info.Get<string>("ID");
				session.User.ID = info.Get<string>("UserID");

#if DEBUG
				Global.WriteLogs(correlationID, "RTU", "Patch a session successful" + "\r\n" + session.ToJson().ToString(Formatting.Indented));
#endif
			}
#if DEBUG
			catch (Exception ex)
			{
				Global.WriteLogs(correlationID, "RTU", "Error occurred while patching a session", ex);
			}
#else
			catch { }
#endif
		}
		#endregion

	}
}
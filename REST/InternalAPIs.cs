#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Client;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{
		static Dictionary<string, IService> Services = new Dictionary<string, IService>();

		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare the requesting information
			var requestInfo = new RequestInfo()
			{
				Session = Global.GetSession(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer),
				Verb = context.Request.HttpMethod,
				ServiceName = string.IsNullOrWhiteSpace(context.Request.QueryString["service-name"]) ? "unknown" : context.Request.QueryString["service-name"],
				ObjectName = string.IsNullOrWhiteSpace(context.Request.QueryString["object-name"]) ? "unknown" : context.Request.QueryString["object-name"],
				Query = context.Request.QueryString.ToDictionary(),
				Header = context.Request.Headers.ToDictionary(),
				CorrelationID = Global.GetCorrelationID(context.Items)
			};

			// SPECIAL: process with sessions
			var isSessionProccessed = requestInfo.ServiceName.IsEquals("users") && requestInfo.ObjectName.IsEquals("session");
			var isSessionInitialized = isSessionProccessed && requestInfo.Verb.IsEquals("GET");

			// authentication & authorization (working with JSON Web Token)
			var accessToken = "";
			try
			{
				// get token
				var appToken = requestInfo.GetParameter("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
				{
					if (!isSessionProccessed)
						throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");
					else if (!requestInfo.Verb.IsEquals("GET"))
						throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");
				}

				// get access token
				else
					accessToken = requestInfo.Session.ParseJSONWebToken(appToken);

				// check existing of the session
				var existIsRequired = !isSessionProccessed || !requestInfo.Session.User.ID.Equals("")
					|| (isSessionInitialized && requestInfo.Session.User.ID.Equals("") && requestInfo.Query.ContainsKey("anonymous"));

				if (!await InternalAPIs.CheckSessionAsync(requestInfo.Session, requestInfo.CorrelationID) && existIsRequired)
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

				// verify session
				var verifyIsRequired = true;
				if (isSessionInitialized && requestInfo.Session.User.ID.Equals(""))
					verifyIsRequired = false;

				if (verifyIsRequired)
					await InternalAPIs.VerifySessionAsync(requestInfo.Session, accessToken, requestInfo.CorrelationID);
			}
			catch (WampException ex)
			{
				context.ShowError(ex, requestInfo);
				return;
			}
			catch (Exception ex)
			{
				context.ShowError(ex);
				return;
			}

			// prepare session identity
			requestInfo.Session.SessionID = string.IsNullOrWhiteSpace(requestInfo.Session.SessionID)
				? UtilityService.GetUUID()
				: requestInfo.Session.SessionID;

			// prepare user principal
			context.User = new UserPrincipal(requestInfo.Session.User);

			// prepare body
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
				using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
				{
					requestInfo.Body = await reader.ReadToEndAsync();
				}

			else if (requestInfo.Verb.IsEquals("GET"))
			{
				requestInfo.Body = context.Request.QueryString["request-body"];
				if (!string.IsNullOrWhiteSpace(requestInfo.Body))
					try
					{
						requestInfo.Body = requestInfo.Body.Url64Decode();
					}
					catch
					{
						requestInfo.Body = "";
					}
			}

			// SPECIALS (PRE): working with sessions
			if (isSessionProccessed)
				try
				{
					// sign-in
					if (requestInfo.Verb.IsEquals("POST"))
					{
						var body = requestInfo.GetBodyExpando();
						if (body == null)
							throw new InvalidSessionException("Sign-in JSON is invalid (empty)");

						if (!body.Has("Timestamp"))
							throw new InvalidSessionException("Sign-in JSON is invalid (no timestamp)");

						var timestamp = body.Get<long>("Timestamp");
						if (DateTime.Now.ToUnixTimestamp() - timestamp > 30)
							throw new SessionExpiredException("Sign-in JSON is invalid (expired)");

						var email = body.Get<string>("Email");
						var password = body.Get<string>("Password");
						var sessionID = body.Get<string>("SessionToken");

						if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(sessionID))
							throw new InvalidSessionException("Sign-in JSON is invalid (email/password/token is null or empty)");

						try
						{
							sessionID = sessionID.Decrypt(Global.AESKey, true);
						}
						catch (Exception ex)
						{
							throw new InvalidSessionException("Sign-in JSON is invalid (session token is invalid)", ex);
						}

						if (!sessionID.Equals(requestInfo.Session.SessionID))
							throw new InvalidDataException("Sign-in JSON is invalid (session token is not issued by the system)");

						try
						{
							email = CryptoService.RSADecrypt(Global.RSA, email);
							password = CryptoService.RSADecrypt(Global.RSA, password);
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Sign-in JSON is invalid (account/password must be encrypted by RSA before sending)", ex);
						}

						requestInfo.Extra = new Dictionary<string, string>()
						{
							{ "Email", email.Encrypt() },
							{ "Password", password.Encrypt() }
						};
					}

					// register the session of anonymous/visitor
					else if (isSessionInitialized && requestInfo.Query.ContainsKey("anonymous") && requestInfo.Session.User.ID.Equals(""))
						requestInfo.Extra = new Dictionary<string, string>()
						{
							{ "SessionID", requestInfo.Query["anonymous"].Decrypt(Global.AESKey.Reverse(), true).Encrypt() },
							{ "AccessToken", accessToken.Encrypt() }
						};
				}
				catch (WampException ex)
				{
					context.ShowError(ex, requestInfo);
					return;
				}
				catch (Exception ex)
				{
					context.ShowError(ex);
					return;
				}

			// do the process
			try
			{
				// call the service
				var json = await InternalAPIs.CallServiceAsync(requestInfo);

				// SPECIALS (POST): working with sessions
				if (isSessionProccessed)
				{
					// sign-in
					if (requestInfo.Verb.IsEquals("POST"))
					{
						// get account information
						requestInfo.Session.User = (await InternalAPIs.CallServiceAsync(
							new RequestInfo(requestInfo.Session, new User() { ID = (json["ID"] as JValue).Value.ToString() })
							{
								ServiceName = "users",
								ObjectName = "mediator",
								Extra = new Dictionary<string, string>()
								{
									{ "Account", "" }
								},
								CorrelationID = requestInfo.CorrelationID
							}
						)).FromJson<User>();

						// update access token
						accessToken = requestInfo.Session.User.GetAccessToken();
						await InternalAPIs.CallServiceAsync(
							new RequestInfo(requestInfo.Session)
							{
								Verb = "PUT",
								ServiceName = "users",
								ObjectName = "session",
								Body = "{\"AccessToken\":\"" + accessToken.Encrypt() + "\"}",
								CorrelationID = requestInfo.CorrelationID
							}
						);

						// update output
						json = new JObject()
						{
							{ "ID", requestInfo.Session.SessionID },
							{ "DeviceID", requestInfo.Session.DeviceID }
						};
						requestInfo.Session.UpdateSessionJson(json, accessToken);
					}

					// other actions
					else
					{
						accessToken = null;

						// sign-out
						if (requestInfo.Verb.IsEquals("DELETE"))
						{
							accessToken = (new User()).GetAccessToken();
							requestInfo.Session.SessionID = (json["ID"] as JValue).Value.ToString();
							json = await InternalAPIs.CallServiceAsync(
								new RequestInfo(requestInfo.Session, new User())
								{
									Verb = "GET",
									ServiceName = "users",
									ObjectName = "session",
									Extra = new Dictionary<string, string>()
									{
										{ "SessionID", requestInfo.Session.SessionID.Encrypt() },
										{ "AccessToken", accessToken.Encrypt() }
									},
									CorrelationID = requestInfo.CorrelationID
								}
							);
						}

						// update output
						requestInfo.Session.UpdateSessionJson(json, accessToken);
					}
				}

				// normalize the result JSON
				json = new JObject()
				{
					{ "Status", "OK" },
					{ "Data", json }
				};

				// write down the JSON
				context.Response.ContentType = "application/json";
				await context.Response.Output.WriteAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
			}
			catch (WampException ex)
			{
				context.ShowError(ex, requestInfo);
			}
			catch (Exception ex)
			{
				context.ShowError(ex);
			}
		}

		#region Helper: get & call service
		internal static async Task<IService> GetServiceAsync(string name)
		{
			if (string.IsNullOrWhiteSpace(name))
				return null;

			if (!InternalAPIs.Services.TryGetValue(name, out IService service))
			{
				await Global.OpenOutgoingChannelAsync();
				lock (InternalAPIs.Services)
				{
					if (!InternalAPIs.Services.TryGetValue(name, out service))
					{
						service = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IService>(new CachedCalleeProxyInterceptor(new ProxyInterceptor(name)));
						InternalAPIs.Services.Add(name, service);
					}
				}
			}
			return service;
		}

		internal static async Task<JObject> CallServiceAsync(RequestInfo requestInfo)
		{
			var name = requestInfo.ServiceName.Trim().ToLower();

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, null, "Call the service [net.vieapps.services." + name + "]" + "\r\n" + requestInfo.ToJson().ToString(Formatting.Indented));
#endif

			var service = await InternalAPIs.GetServiceAsync(name);
			JObject json = null;
			try
			{
				json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);
			}
			catch (WampSessionNotEstablishedException)
			{
				await Task.Delay(456);
				json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);
			}
			catch (Exception)
			{
				throw;
			}

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, null, "Result of the service [net.vieapps.services." + name + "]" + "\r\n" + json.ToString(Formatting.Indented));
#endif

			return json;
		}
		#endregion

		#region Helper: check/verify session & update session's JSON
		internal static async Task<bool> CheckSessionAsync(Session session, string correlationID = null)
		{
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				return false;

			var result = await InternalAPIs.CallServiceAsync(new RequestInfo(session)
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>()
				{
					{ "Exist", "" }
				},
				CorrelationID = correlationID ?? UtilityService.GetUUID()
			});
			return result != null && result["Existed"] is JValue && (result["Existed"] as JValue).Value  != null && (result["Existed"] as JValue).Value.CastAs<bool>() == true;
		}

		internal static async Task VerifySessionAsync(Session session, string accessToken, string correlationID = null)
		{
			await InternalAPIs.CallServiceAsync(new RequestInfo(session)
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>()
				{
					{ "Verify", "" },
					{ "AccessToken", accessToken.Encrypt() }
				},
				CorrelationID = correlationID ?? UtilityService.GetUUID()
			});
		}

		static void UpdateSessionJson(this Session session, JObject json, string accessToken)
		{
			json["ID"] = (json["ID"] as JValue).Value.ToString().Encrypt(Global.AESKey.Reverse(), true);
			json.Add(new JProperty("JWT", session.GetJSONWebToken(accessToken)));
			json.Add(new JProperty("Keys", new JObject()
			{
				{
					"RSA",
					new JObject()
					{
						{ "Exponent", Global.RSAExponent },
						{ "Modulus", Global.RSAModulus }
					}
				},
				{
					"AES",
					new JObject()
					{
						{ "Key", Global.GenerateEncryptionKey(session.SessionID).ToHexa() },
						{ "IV", Global.GenerateEncryptionIV(session.SessionID).ToHexa() }
					}
				},
				{
					"JWT",
					Global.GenerateJWTKey()
				}
			}));
		}
		#endregion

	}
}
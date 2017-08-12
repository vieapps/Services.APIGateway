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
				Header = context.Request.Headers.ToDictionary()
			};

			// SPECIAL: process with sessions
			var isSessionProccessed = requestInfo.ServiceName.IsEquals("users") && requestInfo.ObjectName.IsEquals("session");

			// authentication & authorization (working with JSON Web Token)
			var accessToken = "";
			try
			{
				var appToken = requestInfo.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
				{
					accessToken = await requestInfo.Session.ParseJSONWebTokenAsync(appToken, InternalAPIs.CheckSessionAsync);
					if (requestInfo.Session.User != null)
					{
						var isVerifyRequired = !string.IsNullOrWhiteSpace(requestInfo.Session.User.ID)
							? true
							: isSessionProccessed && requestInfo.Verb.IsEquals("GET")
								? !requestInfo.Query.ContainsKey("anonymous")
								: true;

						if (isVerifyRequired)
							await InternalAPIs.VerifySessionAsync(requestInfo.Session, accessToken);
					}
				}
				else if (!(isSessionProccessed && requestInfo.Verb.IsEquals("GET")))
					throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");
			}
			catch (Exception ex)
			{
				Global.ShowError(context, ex);
				return;
			}

			// prepare identity
			requestInfo.Session.SessionID = string.IsNullOrWhiteSpace(requestInfo.Session.SessionID)
				? requestInfo.Session.SessionID
				: UtilityService.GetUUID();

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
							email = Global.RSADecrypt(email);
							password = Global.RSADecrypt(password);
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
					else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.ContainsKey("anonymous") && requestInfo.Session.User != null && string.IsNullOrWhiteSpace(requestInfo.Session.User.ID))
						requestInfo.Extra = new Dictionary<string, string>()
						{
							{ "SessionID", requestInfo.Query["anonymous"].Decrypt(Global.AESKey, true).Encrypt() },
							{ "AccessToken", accessToken.Encrypt() }
						};
				}
				catch (Exception ex)
				{
					Global.ShowError(context, ex);
					return;
				}

			// call the API
			try
			{
				var service = await InternalAPIs.GetServiceAsync(requestInfo.ServiceName.Trim().ToLower());
				var json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);

				// SPECIALS (POST): working with sessions
				if (isSessionProccessed)
				{
					// sign-in
					if (requestInfo.Verb.IsEquals("POST"))
					{
						// get account information
						requestInfo.Session.User = (await service.ProcessRequestAsync(
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
						await service.ProcessRequestAsync(
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
							json = await service.ProcessRequestAsync(
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

				// normalize and write down
				json = new JObject()
				{
					{ "Status", "OK" },
					{ "Data", json }
				};

				context.Response.ContentType = "application/json";
				await context.Response.Output.WriteAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
			}
			catch (WampException ex)
			{
				Global.ShowError(context, ex, requestInfo);
			}
			catch (Exception ex)
			{
				Global.ShowError(context, ex);
			}
		}

		#region Helper: get service
		static async Task<IService> GetServiceAsync(string name)
		{
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
		#endregion

		#region Helper: check & verify session
		internal static async Task CheckSessionAsync(Session session)
		{
			var service = await InternalAPIs.GetServiceAsync("users");
			var result = await service.ProcessRequestAsync(new RequestInfo(session)
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>()
				{
					{ "Exist", "" }
				}
			});

			var isExisted = result != null && result["Existed"] != null && result["Existed"] is JValue
				&& (result["Existed"] as JValue).Value  != null && (result["Existed"] as JValue).Value.CastAs<bool>() == true;

			if (!isExisted)
				throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
		}

		internal static async Task VerifySessionAsync(Session session, string accessToken)
		{
			var service = await InternalAPIs.GetServiceAsync("users");
			await service.ProcessRequestAsync(new RequestInfo(session)
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>()
				{
					{ "Verify", "" },
					{ "AccessToken", accessToken.Encrypt() }
				}
			});
		}
		#endregion

		#region Helper: update JSON of session
		static void UpdateSessionJson(this Session session, JObject json, string accessToken)
		{
			json = json ?? new JObject()
			{
				{ "ID", session.SessionID },
				{ "DeviceID", session.DeviceID }
			};

			json["ID"] = (json["ID"] as JValue).Value.ToString().Encrypt(Global.AESKey, true);

			session.User = session.User ?? new User();
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
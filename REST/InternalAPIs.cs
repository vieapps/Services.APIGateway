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

			// for working with users (sessions, accounts, activations, ...)
			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;
			if (requestInfo.ServiceName.IsEquals("users"))
			{
				if ("session".IsEquals(requestInfo.ObjectName))
				{
					isSessionProccessed = true;
					isSessionInitialized = requestInfo.Verb.IsEquals("GET");
				}
				else if ("account".IsEquals(requestInfo.ObjectName))
					isAccountProccessed = true;
				else if ("activate".IsEquals(requestInfo.ObjectName))
					isActivationProccessed = true;
			}

			#region authentication & authorization (working with JSON Web Token)
			var accessToken = "";
			try
			{
				// prepare access token
				var isSpecialUser = requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID);
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && isSpecialUser && !requestInfo.Query.ContainsKey("register")
						? false
						: true;

				var appToken = requestInfo.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
					accessToken = requestInfo.Session.ParseJSONWebToken(appToken);
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");

				// validate access token
				if (tokenIsRequired)
				{
					if (!await InternalAPIs.CheckSessionAsync(requestInfo.Session, requestInfo.CorrelationID))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					if (!isSessionInitialized || !(isSpecialUser && requestInfo.Query.ContainsKey("register")))
						await InternalAPIs.VerifySessionAsync(requestInfo.Session, accessToken, requestInfo.CorrelationID);
				}
			}
			catch (Exception ex)
			{
				context.ShowError(ex, requestInfo);
				return;
			}
			#endregion

			// principal & identity
			context.User = new UserPrincipal(requestInfo.Session.User);
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = UtilityService.NewUID;

			#region prepare body
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
				using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
				{
					requestInfo.Body = await reader.ReadToEndAsync();
				}

			else if (requestInfo.Verb.IsEquals("GET") && context.Request.QueryString["x-body"] != null)
				try
				{
					requestInfo.Body = context.Request.QueryString["x-body"].Url64Decode();
				}
				catch
				{
					requestInfo.Body = "";
				}
			#endregion

			#region SPECIALS: working with sessions/accounts/activations
			if (isSessionProccessed)
				try
				{
					// sign-in
					if (requestInfo.Verb.IsEquals("POST"))
						requestInfo.PrepareSignIn();

					// register the session
					else if (isSessionInitialized)
						requestInfo.PrepareSessionOnRegister(accessToken);
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
					return;
				}

			else if (isAccountProccessed)
				try
				{
					if (requestInfo.Verb.IsEquals("PUT"))
					{
						// reset password
						if ("reset".IsEquals(requestInfo.GetObjectIdentity()))
							requestInfo.PrepareResetPassword();

						// update password

						// update email

					}
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
					return;
				}
			#endregion

			// process the request
			try
			{
				// call the service
				var json = await InternalAPIs.CallServiceAsync(requestInfo);

				#region SPECIALS: working with sessions/accounts/activations
				if (isActivationProccessed)
				{
					requestInfo.Session.SessionID = (json["SessionID"] as JValue).Value as string;
					requestInfo.Session.DeviceID = (json["DeviceID"] as JValue).Value as string;
					accessToken = await requestInfo.PrepareUserInformationAsync((json["UserID"] as JValue).Value as string);
					json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
				}
				else if (isSessionProccessed)
				{
					accessToken = null;

					// sign-in
					if (requestInfo.Verb.IsEquals("POST"))
					{
						accessToken = await requestInfo.PrepareUserInformationAsync((json["ID"] as JValue).Value as string);
						json = new JObject()
						{
							{ "ID", requestInfo.Session.SessionID },
							{ "DeviceID", requestInfo.Session.DeviceID }
						};
					}

					// sign-out
					else if (requestInfo.Verb.IsEquals("DELETE"))
					{
						accessToken = (new User()).GetAccessToken();
						json = await requestInfo.PrepareSessionOnSignOutAsync((json["ID"] as JValue).Value as string, accessToken);
					}

					// update session's JSON
					requestInfo.Session.UpdateSessionJson(json, accessToken);
				}
				#endregion

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
			catch (Exception ex)
			{
				context.ShowError(ex, requestInfo);
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

		#region Helper: working with sessions
		internal static async Task<bool> CheckSessionAsync(Session session, string correlationID = null)
		{
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				return false;

			var result = await InternalAPIs.CallServiceAsync(new RequestInfo(session)
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>() { { "Exist", "" } },
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

		static void PrepareSessionOnRegister(this RequestInfo requestInfo, string accessToken)
		{
			if (requestInfo.Query.ContainsKey("register") && (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)))
				requestInfo.Extra = new Dictionary<string, string>()
				{
					{ "SessionID", requestInfo.Query["register"].Decrypt(Global.AESKey.Reverse(), true).Encrypt() },
					{ "AccessToken", accessToken.Encrypt() }
				};
		}

		static async Task<JObject> PrepareSessionOnSignOutAsync(this RequestInfo requestInfo, string sessionID, string accessToken)
		{
			return await InternalAPIs.CallServiceAsync(new RequestInfo(new Session(requestInfo.Session) { SessionID = sessionID, User = new User() })
			{
				ServiceName = "users",
				ObjectName = "session",
				Extra = new Dictionary<string, string>()
				{
					{ "SessionID", requestInfo.Session.SessionID.Encrypt() },
					{ "AccessToken", accessToken.Encrypt() }
				},
				CorrelationID = requestInfo.CorrelationID
			});
		}

		static void UpdateSessionJson(this Session session, JObject json, string accessToken)
		{
			json["ID"] = session.SessionID.Encrypt(Global.AESKey.Reverse(), true);
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
			json.Add(new JProperty("JWT", session.GetJSONWebToken(accessToken)));
		}
		#endregion

		#region Helper: working with accounts
		static void PrepareSignIn(this RequestInfo requestInfo)
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
			var sessionID = body.Get<string>("Session");

			if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(sessionID))
				throw new InvalidSessionException("Sign-in JSON is invalid (email/password/token is null or empty)");

			try
			{
				sessionID = sessionID.Decrypt(Global.GenerateEncryptionKey(requestInfo.Session.SessionID), Global.GenerateEncryptionIV(requestInfo.Session.SessionID));
				sessionID = sessionID.Decrypt(Global.AESKey.Reverse(), true);
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

		static void PrepareResetPassword(this RequestInfo requestInfo)
		{
			var body = requestInfo.GetBodyExpando();
			if (body == null)
				throw new InvalidSessionException("Reset JSON is invalid (empty)");

			if (!body.Has("Timestamp"))
				throw new InvalidSessionException("Reset JSON is invalid (no timestamp)");

			var timestamp = body.Get<long>("Timestamp");
			if (DateTime.Now.ToUnixTimestamp() - timestamp > 30)
				throw new SessionExpiredException("Reset JSON is invalid (expired)");

			var email = body.Get<string>("Email");
			var sessionID = body.Get<string>("Session");
			var captcha = body.Get<string>("Captcha");

			if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(sessionID) || string.IsNullOrWhiteSpace(captcha))
				throw new InvalidSessionException("Reset JSON is invalid (email/token/captcha is null or empty)");

			try
			{
				sessionID = sessionID.Decrypt(Global.GenerateEncryptionKey(requestInfo.Session.SessionID), Global.GenerateEncryptionIV(requestInfo.Session.SessionID));
				sessionID = sessionID.Decrypt(Global.AESKey.Reverse(), true);
			}
			catch (Exception ex)
			{
				throw new InvalidSessionException("Reset JSON is invalid (session token is invalid)", ex);
			}

			if (!sessionID.Equals(requestInfo.Session.SessionID))
				throw new InvalidDataException("Reset JSON is invalid (session token is not issued by the system)");

			try
			{
				captcha = captcha.Decrypt(Global.GenerateEncryptionKey(requestInfo.Session.SessionID), Global.GenerateEncryptionIV(requestInfo.Session.SessionID));
			}
			catch (Exception ex)
			{
				throw new InvalidSessionException("Reset JSON is invalid (captcha is invalid)", ex);
			}

			try
			{
				var info = JObject.Parse(captcha);
				if (!Captcha.IsCodeValid((info["Registered"] as JValue).Value as string, (info["Input"] as JValue).Value as string))
					throw new InformationInvalidException("Captcha code is invalid");
			}
			catch (Exception)
			{
				throw;
			}

			try
			{
				email = CryptoService.RSADecrypt(Global.RSA, email);
			}
			catch (Exception ex)
			{
				throw new InvalidDataException("Reset JSON is invalid (email must be encrypted by RSA before sending)", ex);
			}

			requestInfo.Extra = new Dictionary<string, string>()
			{
				{ "Email", email.Encrypt() }
			};
		}

		static async Task<string> PrepareUserInformationAsync(this RequestInfo requestInfo, string userID)
		{
			// get account information
			var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, new User() { ID = userID })
			{
				ServiceName = "users",
				ObjectName = "mediator",
				Extra = new Dictionary<string, string>()
				{
					{ "Account", "" },
					{ "Full", "" }
				},
				CorrelationID = requestInfo.CorrelationID
			});

			// assign user information and get access token
			requestInfo.Session.User = json.FromJson<User>();
			var accessToken = requestInfo.Session.User.GetAccessToken();

			// update access token
			await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
			{
				Verb = "PUT",
				ServiceName = "users",
				ObjectName = "session",
				Body = "{\"AccessToken\":\"" + accessToken.Encrypt() + "\"}",
				CorrelationID = requestInfo.CorrelationID
			});

			// return the access token
			return accessToken;
		}
		#endregion

	}
}
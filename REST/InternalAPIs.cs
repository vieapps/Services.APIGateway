#region Related components
using System;
using System.IO;
using System.Web;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;
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

			#region prepare the requesting information
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

			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;

			if (requestInfo.ServiceName.IsEquals("users"))
			{
				if ("session".IsEquals(requestInfo.ObjectName))
				{
					isSessionProccessed = true;
					isSessionInitialized = requestInfo.Verb.IsEquals("GET");
				}
				else if ("account".IsEquals(requestInfo.ObjectName))
					isAccountProccessed = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT");
				else if ("activate".IsEquals(requestInfo.ObjectName))
					isActivationProccessed = requestInfo.Verb.IsEquals("GET");
			}
			#endregion

			#region prepare token
			var accessToken = "";
			try
			{
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

				if (tokenIsRequired)
				{
					if (!await InternalAPIs.CheckSessionExistAsync(requestInfo.Session))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					if (!isSessionInitialized || !(isSpecialUser && requestInfo.Query.ContainsKey("register")))
						await InternalAPIs.VerifySessionIntegrityAsync(requestInfo.Session, accessToken);
				}
			}
			catch (Exception ex)
			{
				context.ShowError(ex, requestInfo);
				return;
			}
			#endregion

			#region prepare others (principal, identity, body)
			context.User = new UserPrincipal(requestInfo.Session.User);
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = UtilityService.NewUID;

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

			#region [extra] prepare information of an account
			if (isAccountProccessed)
				try
				{
					var requestBody = requestInfo.GetBodyExpando();
					if (requestBody == null)
						throw new InvalidSessionException("Request JSON is invalid (empty)");

					// verify time-stamp
					if (!requestBody.Has("Timestamp"))
						throw new InvalidSessionException("Request JSON is invalid (no timestamp)");

					var timestamp = requestBody.Get<long>("Timestamp");
					if (DateTime.Now.ToUnixTimestamp() - timestamp > 30)
						throw new SessionExpiredException("Reset JSON is invalid (expired)");

					// verify session token
					var sessionID = requestBody.Get<string>("Session");
					if (string.IsNullOrWhiteSpace(sessionID))
						throw new InvalidSessionException("Request JSON is invalid (session token is null or empty)");

					try
					{
						sessionID = sessionID.Decrypt(Global.GenerateEncryptionKey(requestInfo.Session.SessionID), Global.GenerateEncryptionIV(requestInfo.Session.SessionID));
						sessionID = sessionID.Decrypt(Global.AESKey.Reverse(), true);
					}
					catch (Exception ex)
					{
						throw new InvalidSessionException("Request JSON is invalid (session token is invalid)", ex);
					}

					if (!sessionID.Equals(requestInfo.Session.SessionID))
						throw new InvalidDataException("Request JSON is invalid (session token is not issued by the system)");

					// verify captcha
					var captcha = requestBody.Get<string>("Captcha");
					if (!string.IsNullOrWhiteSpace(captcha))
					{
						try
						{
							captcha = captcha.Decrypt(Global.GenerateEncryptionKey(requestInfo.Session.SessionID), Global.GenerateEncryptionIV(requestInfo.Session.SessionID));
						}
						catch (Exception ex)
						{
							throw new InvalidSessionException("Request JSON is invalid (captcha is invalid)", ex);
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
					}

					// prepare email
					var email = requestBody.Get<string>("Email");
					if (!string.IsNullOrWhiteSpace(email))
						try
						{
							email = CryptoService.RSADecrypt(Global.RSA, email);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
							{
								{ "Email", email.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (email must be encrypted by RSA before sending)", ex);
						}

					// prepare password
					var password = requestBody.Get<string>("Password");
					if (!string.IsNullOrWhiteSpace(password))
						try
						{
							password = CryptoService.RSADecrypt(Global.RSA, password);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
							{
								{ "Password", password.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// prepare old-password
					var oldPassword = requestBody.Get<string>("OldPassword");
					if (!string.IsNullOrWhiteSpace(oldPassword))
						try
						{
							oldPassword = CryptoService.RSADecrypt(Global.RSA, oldPassword);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
							{
								{ "OldPassword", oldPassword.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// preapare
					var objectIdentity = requestInfo.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (requestBody.Get<string>("Session").Equals(requestInfo.GetHeaderParameter("x-create")))
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
							{
								{ "x-create", "" }
							};
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
						{
							{ "x-invite", "" }
						};

					// prepare to reset password
					else if ("reset".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(captcha)))
						throw new InvalidSessionException("Request JSON is invalid (email/captcha is null or empty)");

					// prepare to update password
					else if ("password".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(password)))
						throw new InvalidSessionException("Request JSON is invalid (password is null or empty)");

					// prepare to update email
					else if ("email".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(email)))
						throw new InvalidSessionException("Request JSON is invalid (password/email is null or empty)");
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
					return;
				}
			#endregion

			// process the request of session
			if (isSessionProccessed)
			{
				if (requestInfo.Verb.IsEquals("GET"))
					await InternalAPIs.RegisterSessionAsync(context, requestInfo, accessToken);
				else if (requestInfo.Verb.IsEquals("POST"))
					await InternalAPIs.SignSessionInAsync(context, requestInfo);
				else if (requestInfo.Verb.IsEquals("DELETE"))
					await InternalAPIs.SignSessionOutAsync(context, requestInfo);
				else
					context.ShowError(new MethodNotAllowedException(requestInfo.Verb), requestInfo);
			}

			// process the request of activation
			else if (isActivationProccessed)
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
					requestInfo.Session.DeviceID = "pwa@" + (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true);

				// activate
				await InternalAPIs.ActivateAsync(context, requestInfo);
			}

			// process the request of services
			else
				try
				{
					await context.WriteResponseAsync(await InternalAPIs.CallServiceAsync(requestInfo));
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
				}
		}

		#region Register a session
		async static Task RegisterSessionAsync(HttpContext context, RequestInfo requestInfo, string accessToken)
		{
			// session of visitor/system account
			if ((requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)))
				try
				{
					// prepare access token
					accessToken = string.IsNullOrWhiteSpace(accessToken)
						? User.GetAccessToken(requestInfo.Session.User, Global.RSA, Global.AESKey)
						: accessToken;

					// generate session
					var session = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "IssuedAt", DateTime.Now },
						{ "RenewedAt", DateTime.Now },
						{ "ExpiredAt", DateTime.Now.AddDays(60) },
						{ "UserID", requestInfo.Session.User.ID },
						{ "AccessToken", accessToken },
						{ "IP", requestInfo.Session.IP },
						{ "DeviceID", requestInfo.Session.DeviceID },
						{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
						{ "Online", true }
					};

					// initialize session
					if (context.Request.QueryString["register"] == null)
					{
						// generate device identity
						if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
						{
							requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true) + "@pwa";
							session["DeviceID"] = requestInfo.Session.DeviceID;
						}

						// update cache
						await Global.Cache.SetAbsoluteAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 2);
					}

					// register session
					else
					{
						// validate
						if (!requestInfo.Session.SessionID.Equals(context.Request.QueryString["register"].Decrypt(Global.AESKey.Reverse(), true)))
							throw new InvalidRequestException();

						// register with user service
						await Task.WhenAll(
								InternalAPIs.CallServiceAsync(requestInfo.Session, "users", "session", "POST", session.ToString(Formatting.None)),
								Global.Cache.SetAbsoluteAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180)
							);
					}

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json);
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
				}

			// session of authenticated account
			else
				try
				{
					// call service to get session
					var session = await InternalAPIs.CallServiceAsync(requestInfo.Session, "users", "session");
					var jsonUserID = session?["UserID"];
					var jsonAccessToken = session?["AccessToken"];

					// verify access token
					if (jsonUserID == null || !(jsonUserID is JValue) || (jsonUserID as JValue).Value == null || !requestInfo.Session.User.ID.Equals((jsonUserID as JValue).Value as string))
						throw new InvalidTokenException();
					else if (jsonAccessToken == null || !(jsonAccessToken is JValue) || (jsonAccessToken as JValue).Value == null || !accessToken.Equals(((jsonAccessToken as JValue).Value as string).Decrypt()))
						throw new TokenRevokedException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(60);
					session["AccessToken"] = ((jsonAccessToken as JValue).Value as string).Decrypt();
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["Online"] = true;

					// register with user service
					await Task.WhenAll(
							InternalAPIs.CallServiceAsync(requestInfo.Session, "users", "session", "POST", session.ToString(Formatting.None)),
							Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180)
						);

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json);
				}
				catch (Exception ex)
				{
					context.ShowError(ex, requestInfo);
				}
		}
		#endregion

		#region Sign a session in
		async static Task SignSessionInAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// validate
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

				// call service to perform sign in
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "users",
					ObjectName = "session",
					Verb = "PUT",
					Body = (new JObject()
					{
						{ "Email", email.Encrypt() },
						{ "Password", password.Encrypt() }
					}).ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				});

				// clear cached of current session
				await Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID);
				
				// prepare session
				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.SessionID = UtilityService.NewUID;
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Global.RSA, Global.AESKey);

				// register new session
				var session = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "IssuedAt", DateTime.Now },
					{ "RenewedAt", DateTime.Now },
					{ "ExpiredAt", DateTime.Now.AddDays(60) },
					{ "UserID", requestInfo.Session.User.ID },
					{ "AccessToken", accessToken },
					{ "IP", requestInfo.Session.IP },
					{ "DeviceID", requestInfo.Session.DeviceID },
					{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
					{ "Online", true }
				};

				await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "users",
					ObjectName = "session",
					Verb = "POST",
					Body = session.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				});

				await Task.WhenAll(
						Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180),
						requestInfo.Session.SendOnlineStatusAsync(true)
					);

				// response
				json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);

				await Task.WhenAll(
						context.WriteResponseAsync(json),
						Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
					);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP)
					? await Global.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP)
					: 0;
				attempt++;

				await Task.WhenAll(
						Task.Delay(567 + ((attempt - 1) * 5000)),
						Global.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
					);

				// show error
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Sign a session out
		async static Task SignSessionOutAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if ((requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)))
					throw new InvalidRequestException();

				// call service to perform sign out
				await InternalAPIs.CallServiceAsync(requestInfo.Session, "users", "session", "DELETE");

				await Task.WhenAll(
						Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID),
						requestInfo.Session.SendOnlineStatusAsync(false)
					);

				// create a new session
				requestInfo.Session.SessionID = UtilityService.NewUID;
				requestInfo.Session.User = new User();

				// register the new session of visitor
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Global.RSA, Global.AESKey);
				var session = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "IssuedAt", DateTime.Now },
					{ "RenewedAt", DateTime.Now },
					{ "ExpiredAt", DateTime.Now.AddDays(60) },
					{ "UserID", requestInfo.Session.User.ID },
					{ "AccessToken", accessToken },
					{ "IP", requestInfo.Session.IP },
					{ "DeviceID", requestInfo.Session.DeviceID },
					{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
					{ "Online", true }
				};
				await Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180);

				// response
				var json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);

				await context.WriteResponseAsync(json);
			}
			catch (Exception ex)
			{
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Activation
		async static Task ActivateAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// call service to activate
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "users", "activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID));

				// update user information & get access token
				requestInfo.Session.User = json.FromJson<User>();
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Global.RSA, Global.AESKey);

				// register the session
				var session = (new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "IssuedAt", DateTime.Now },
					{ "RenewedAt", DateTime.Now },
					{ "ExpiredAt", DateTime.Now.AddDays(60) },
					{ "UserID", requestInfo.Session.User.ID },
					{ "AccessToken", accessToken },
					{ "IP", requestInfo.Session.IP },
					{ "DeviceID", requestInfo.Session.DeviceID },
					{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
					{ "Online", true }
				}).ToString(Formatting.None);
				await Task.WhenAll(
						InternalAPIs.CallServiceAsync(requestInfo.Session, "users", "session", "POST", session),
						Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session, 180),
						requestInfo.Session.SendOnlineStatusAsync(true)
					);

				// response
				json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);
				await context.WriteResponseAsync(json);
			}
			catch (Exception ex)
			{
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Verify a session
		internal static async Task<bool> CheckSessionExistAsync(Session session)
		{
			// pre-check
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				return false;
			else if (await Global.Cache.ExistsAsync("Session#" + session.SessionID))
				return true;

			// check with user service
			var result = await InternalAPIs.CallServiceAsync(session, "users", "session", "GET", null, new Dictionary<string, string>()
			{
				{ "Exist", "" }
			});

			var isExisted = result?["Existed"];
			return isExisted != null && isExisted is JValue && (isExisted as JValue).Value != null && (isExisted as JValue).Value.CastAs<bool>() == true;
		}

		internal static async Task VerifySessionIntegrityAsync(Session session, string accessToken)
		{
			// pre-check
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				throw new SessionNotFoundException();
			else if (string.IsNullOrWhiteSpace(accessToken))
				throw new TokenNotFoundException();

			// check with cached
			var cached = await Global.Cache.GetAsync<string>("Session#" + session.SessionID);
			if (!string.IsNullOrWhiteSpace(cached))
			{
				var info = cached.ToExpandoObject();
				if (info.Get<DateTime>("ExpiredAt") < DateTime.Now)
					throw new SessionExpiredException();
				else if (!accessToken.Equals(info.Get<string>("AccessToken")))
					throw new TokenRevokedException();
			}

			// check with user service
			else
				await InternalAPIs.CallServiceAsync(session, "users", "session", "GET", null, new Dictionary<string, string>()
				{
					{ "Verify", "" },
					{ "AccessToken", accessToken.Encrypt() }
				});
		}
		#endregion

		#region Helper: call service
		internal static async Task<JObject> CallServiceAsync(RequestInfo requestInfo)
		{
			var name = requestInfo.ServiceName.Trim().ToLower();

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, null, "Call the service [net.vieapps.services." + name + "]" + "\r\n" + requestInfo.ToJson().ToString(Formatting.Indented));
#endif

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

			JObject json = null;
			try
			{
				json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);
			}
			catch (WampSessionNotEstablishedException)
			{
				await Task.Delay(567);
				json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);
			}
			catch (Exception)
			{
				throw;
			}

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, null, "Result of the service [net.vieapps.services." + name + "]" + "\r\n" + (json != null ? json.ToString(Formatting.Indented) : "None"));
#endif

			return json;
		}

		internal static Task<JObject> CallServiceAsync(Session session, string serviceName, string objectName, string verb = "GET", string body = null, Dictionary<string, string> extra = null)
		{
			return InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb)
			{
				Body = body ?? "",
				Extra = extra ?? new Dictionary<string, string>(),
				CorrelationID = Global.GetCorrelationID()
			});
		}
		#endregion

		#region Helper: working with response JSON, online status, ...
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

		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
		{
			return session.User == null || session.User.ID.Equals("")
				? Task.CompletedTask
				: Global.SendInterCommunicateMessageAsync(new CommunicateMessage()
				{
					ServiceName = "Users",
					Type = "Account",
					Data = new JObject()
					{
						{ "Verb", "Status" },
						{ "UserID", session.User.ID },
						{ "SessionID", session.SessionID },
						{ "DeviceID", session.DeviceID },
						{ "AppName", session.AppName },
						{ "AppPlatform", session.AppPlatform },
						{ "IP", session.IP },
						{ "IsOnline", isOnline },
					}
				});
		}

		static async Task WriteResponseAsync(this HttpContext context, JObject json)
		{
			context.Response.ContentType = "application/json";
			await context.Response.Output.WriteAsync((new JObject()
			{
				{ "Status", "OK" },
				{ "Data", json }
			}).ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
		}
		#endregion

	}
}
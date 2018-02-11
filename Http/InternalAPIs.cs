#region Related components
using System;
using System.IO;
using System.Web;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

using net.vieapps.Services.Base.AspNet;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{
		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			// track
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);
			await Task.WhenAll(
				Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Begin process [{context.Request.HttpMethod}]: {context.Request.Url.Scheme}://{context.Request.Url.Host + context.Request.RawUrl}"),
				Base.AspNet.Global.IsInfoLogEnabled ? Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", $"Begin process [{context.Request.HttpMethod}]: {context.Request.Url.Scheme}://{context.Request.Url.Host + context.Request.RawUrl}") : Task.CompletedTask
			).ConfigureAwait(false);

			#region prepare the requesting information
			var request = new RequestInfo()
			{
				Session = context.GetSession(),
				Verb = context.Request.HttpMethod,
				ServiceName = string.IsNullOrWhiteSpace(context.Request.QueryString["service-name"]) ? "unknown" : context.Request.QueryString["service-name"],
				ObjectName = string.IsNullOrWhiteSpace(context.Request.QueryString["object-name"]) ? "unknown" : context.Request.QueryString["object-name"],
				Query = new Dictionary<string, string>(context.Request.QueryString.ToDictionary(), StringComparer.OrdinalIgnoreCase),
				Header = new Dictionary<string, string>(context.Request.Headers.ToDictionary(), StringComparer.OrdinalIgnoreCase),
				CorrelationID = correlationID
			};

			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;

			if (request.ServiceName.IsEquals("users"))
			{
				if ("session".IsEquals(request.ObjectName))
				{
					isSessionProccessed = true;
					isSessionInitialized = request.Verb.IsEquals("GET");
				}
				else if ("account".IsEquals(request.ObjectName))
					isAccountProccessed = request.Verb.IsEquals("POST") || request.Verb.IsEquals("PUT");
				else if ("activate".IsEquals(request.ObjectName))
					isActivationProccessed = request.Verb.IsEquals("GET");
			}
			#endregion

			#region prepare token
			var accessToken = "";
			try
			{
				var isSpecialUser = request.Session.User.ID.Equals("") || request.Session.User.IsSystemAccount;
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && isSpecialUser && !request.Query.ContainsKey("register")
						? false
						: request.ServiceName.IsEquals("indexes")
							? false
							: true;

				var appToken = request.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
					accessToken = request.Session.ParseJSONWebToken(appToken);
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");

				if (tokenIsRequired)
				{
					if (!await InternalAPIs.CheckSessionExistAsync(request.Session).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					if (!isSessionInitialized || !(isSpecialUser && request.Query.ContainsKey("register")))
						await InternalAPIs.VerifySessionIntegrityAsync(request.Session, accessToken).ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				await Task.WhenAll(
					Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "End process => Error occurred while preparing token", ex),
					Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process => Error occurred while preparing token", ex)
				).ConfigureAwait(false);
				context.ShowError(ex, request, false);
				return;
			}
			#endregion

			#region prepare others (principal, identity, body)
			context.User = new UserPrincipal(request.Session.User);
			if (string.IsNullOrWhiteSpace(request.Session.SessionID))
				request.Session.SessionID = UtilityService.NewUID;

			if (request.Verb.IsEquals("POST") || request.Verb.IsEquals("PUT"))
				try
				{
					using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
					{
						request.Body = await reader.ReadToEndAsync().ConfigureAwait(false);
					}
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while parsing body of the request", ex),
						Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "Error occurred while parsing body of the request", ex)
					).ConfigureAwait(false);
				}

			else if (request.Verb.IsEquals("GET") && context.Request.QueryString["x-body"] != null)
				try
				{
					request.Body = context.Request.QueryString["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while parsing body of the 'x-body' parameter", ex),
						Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "Error occurred while parsing body of the 'x-body' parameter", ex)
					).ConfigureAwait(false);
				}
			#endregion

			await Task.WhenAll(
				Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Request:\r\n{request.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"),
				Base.AspNet.Global.IsDebugLogEnabled ? Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", $"Request:\r\n{request.ToJson().ToString(Formatting.Indented)}") : Task.CompletedTask
			).ConfigureAwait(false);

			#region [extra] verify captcha
			// verfy captcha
			var captchaIsValid = false;
			if (request.Header.ContainsKey("x-captcha"))
				try
				{
					request.Header.TryGetValue("x-captcha-registered", out string registered);
					request.Header.TryGetValue("x-captcha-input", out string input);
					if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(input))
						throw new InvalidSessionException("Captcha code is invalid");

					try
					{
						registered = registered.Decrypt(Base.AspNet.Global.GenerateEncryptionKey(request.Session.SessionID), Base.AspNet.Global.GenerateEncryptionIV(request.Session.SessionID));
						input = input.Decrypt(Base.AspNet.Global.GenerateEncryptionKey(request.Session.SessionID), Base.AspNet.Global.GenerateEncryptionIV(request.Session.SessionID));
					}
					catch (Exception ex)
					{
						throw new InvalidSessionException("Captcha code is invalid", ex);
					}

					captchaIsValid = CaptchaService.IsCodeValid(registered, input)
						? true
						: throw new InformationInvalidException("Captcha code is invalid");
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "End process => Error occurred while verifying captcha", ex),
						Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process => Error occurred while verifying captcha", ex)
					).ConfigureAwait(false);
					context.ShowError(ex, request);
					return;
				}
			#endregion

			#region [extra] prepare information of an account
			if (isAccountProccessed)
				try
				{
					var requestBody = request.GetBodyExpando();
					if (requestBody == null)
						throw new InvalidSessionException("Request JSON is invalid (empty)");

					// prepare email
					var email = requestBody.Get<string>("Email");
					if (!string.IsNullOrWhiteSpace(email))
						try
						{
							email = Base.AspNet.Global.RSA.Decrypt(email);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Email", email.Encrypt(Base.AspNet.Global.EncryptionKey) }
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
							password = Base.AspNet.Global.RSA.Decrypt(password);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Password", password.Encrypt(Base.AspNet.Global.EncryptionKey) }
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
							oldPassword = Base.AspNet.Global.RSA.Decrypt(oldPassword);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "OldPassword", oldPassword.Encrypt(Base.AspNet.Global.EncryptionKey) }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// prepare privileges
					var privileges = requestBody.Get<string>("Privileges");
					if (!string.IsNullOrWhiteSpace(privileges))
						try
						{
							privileges = Base.AspNet.Global.RSA.Decrypt(privileges);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Privileges", privileges.Encrypt(Base.AspNet.Global.EncryptionKey) }
							};
						}
						catch { }

					// prepare information of related service
					var relatedInfo = request.Query.ContainsKey("related-service")
						? requestBody.Get<string>("RelatedInfo")
						: null;
					if (!string.IsNullOrWhiteSpace(relatedInfo))
						try
						{
							relatedInfo = Base.AspNet.Global.RSA.Decrypt(relatedInfo);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "RelatedInfo", relatedInfo.Encrypt(Base.AspNet.Global.EncryptionKey) }
							};
						}
						catch { }

					// preapare
					var objectIdentity = request.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (!captchaIsValid)
							throw new InvalidSessionException("Captcha code is invalid");

						if (request.Session.SessionID.Encrypt(Base.AspNet.Global.EncryptionKey.Reverse(), true).Equals(request.GetHeaderParameter("x-create")))
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "x-create", "" }
							};
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
						{
							{ "x-invite", "" }
						};

					// prepare to reset password
					else if ("reset".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(email) || !captchaIsValid))
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
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "End process => Error occurred while processing account", ex),
						Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process => Error occurred while processing account", ex)
					).ConfigureAwait(false);
					context.ShowError(ex, request);
					return;
				}
			#endregion

			// process the request of session
			if (isSessionProccessed)
				switch (request.Verb)
				{
					case "GET":
						await InternalAPIs.RegisterSessionAsync(context, request, accessToken).ConfigureAwait(false);
						break;

					case "POST":
						await InternalAPIs.SignSessionInAsync(context, request).ConfigureAwait(false);
						break;

					case "PUT":
						await InternalAPIs.ValidateOTPSessionAsync(context, request).ConfigureAwait(false);
						break;

					case "DELETE":
						await InternalAPIs.SignSessionOutAsync(context, request).ConfigureAwait(false);
						break;

					default:
						context.ShowError(new MethodNotAllowedException(request.Verb), request, false);
						break;
				}

			// process the request of activation
			else if (isActivationProccessed)
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(request.Session.DeviceID))
					request.Session.DeviceID = (request.Session.AppName + "/" + request.Session.AppPlatform + "@" + (request.Session.AppAgent ?? "N/A")).GetHMACSHA384(request.Session.SessionID, true) + "@pwa";

				// activate
				try
				{
					await InternalAPIs.ActivateAsync(context, request).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process => Error occurred while activating", ex).ConfigureAwait(false);
					context.ShowError(ex, request);
				}
			}

			// process the request of services
			else
				try
				{
					// process
					var response = await InternalAPIs.CallServiceAsync(request).ConfigureAwait(false);

					// special: request to update sessions of an account
					if (isAccountProccessed && request.Verb.IsEquals("PUT"))
						await InternalAPIs.RequestUpdateSessionsAsync(request).ConfigureAwait(false);

					// response
					await context.WriteResponseAsync(response).ConfigureAwait(false);

					if (Base.AspNet.Global.IsDebugLogEnabled)
						await Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", $"End process => Response:\r\n{response.ToString(Formatting.Indented)}").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process => Error occurred while processing", ex).ConfigureAwait(false);
					context.ShowError(ex, request);
				}
				finally
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "End process"),
						Base.AspNet.Global.IsInfoLogEnabled && !Base.AspNet.Global.IsDebugLogEnabled  ? Base.AspNet.Global.WriteLogsAsync(correlationID, "Internal", "End process") : Task.CompletedTask
					).ConfigureAwait(false);
				}
		}

		#region Register a session
		static async Task RegisterSessionAsync(HttpContext context, RequestInfo requestInfo, string accessToken)
		{
			// session of visitor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
				try
				{
					// prepare access token
					accessToken = string.IsNullOrWhiteSpace(accessToken)
						? User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey)
						: accessToken;

					// generate session
					var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken);

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
						await Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 2).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						if (!requestInfo.Session.SessionID.Equals(context.Request.QueryString["register"].Decrypt(Base.AspNet.Global.EncryptionKey.Reverse(), true)))
							throw new InvalidRequestException();

						// register with user service
						var body = session.ToString(Formatting.None);
						await Task.WhenAll(
							InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", body, new Dictionary<string, string>()
							{
								{ "Signature", body.GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
							}, requestInfo.CorrelationID),
							Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, body, 180)
						).ConfigureAwait(false);
					}

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "End process => Error occurred while registering session", ex).ConfigureAwait(false);
					context.ShowError(ex, requestInfo);
				}

			// session of authenticated account
			else
				try
				{
					// call service to get session
					var session = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "GET", requestInfo.Query, requestInfo.Header, null, new Dictionary<string, string>()
					{
						{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
					}, requestInfo.CorrelationID)).ConfigureAwait(false);
					var jsonUserID = session?["UserID"];
					var jsonAccessToken = session?["AccessToken"];

					// verify access token
					if (jsonUserID == null || !(jsonUserID is JValue) || (jsonUserID as JValue).Value == null || !requestInfo.Session.User.ID.Equals((jsonUserID as JValue).Value as string))
						throw new InvalidTokenException();
					else if (jsonAccessToken == null || !(jsonAccessToken is JValue) || (jsonAccessToken as JValue).Value == null || !accessToken.Equals(((jsonAccessToken as JValue).Value as string).Decrypt(Base.AspNet.Global.EncryptionKey)))
						throw new TokenRevokedException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(60);
					session["AccessToken"] = ((jsonAccessToken as JValue).Value as string).Decrypt(Base.AspNet.Global.EncryptionKey);
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["OSInfo"] = context.GetOSInfo() + " [" + context.Request.UserAgent + "]";
					session["Online"] = true;

					// register with user service
					var body = session.ToString(Formatting.None);
					await Task.WhenAll(
						InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", body, new Dictionary<string, string>()
						{
							{ "Signature", body.GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
						}, requestInfo.CorrelationID),
						Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, body, 180)
					).ConfigureAwait(false);

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "End process => Error occurred while registering session", ex).ConfigureAwait(false);
					context.ShowError(ex, requestInfo);
				}
		}
		#endregion

		#region Sign a session in
		static async Task SignSessionInAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// validate
				var request = requestInfo.GetBodyExpando();
				if (request == null)
					throw new InvalidTokenException("Sign-in JSON is invalid (empty)");

				var email = request.Get<string>("Email");
				var password = request.Get<string>("Password");

				if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
					throw new InvalidTokenException("Sign-in JSON is invalid (email/password is null or empty)");

				try
				{
					email = Base.AspNet.Global.RSA.Decrypt(email);
					password = Base.AspNet.Global.RSA.Decrypt(password);
				}
				catch (Exception ex)
				{
					throw new InvalidTokenException("Sign-in JSON is invalid (account/password must be encrypted by RSA before sending)", ex);
				}

				// call service to perform sign in
				var body = new JObject()
				{
					{ "Type", request.Get("Type", "BuiltIn") },
					{ "Email", email.Encrypt(Base.AspNet.Global.EncryptionKey) },
					{ "Password", password.Encrypt(Base.AspNet.Global.EncryptionKey) },
				}.ToString(Formatting.None);
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "Session",
					Verb = "PUT",
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}).ConfigureAwait(false);

				// two-factors authentication
				var require2FA = json["Require2FA"] != null
					? (json["Require2FA"] as JValue).Value.CastAs<bool>()
					: false;

				if (require2FA)
					json = new JObject()
					{
						{ "ID", (json["ID"] as JValue).Value as string },
						{ "Require2FA", true },
						{ "Providers", json["Providers"] as JArray }
					};

				else
				{
					// register new session
					await Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID).ConfigureAwait(false);

					requestInfo.Session.User = json.FromJson<User>();
					requestInfo.Session.SessionID = UtilityService.NewUID;
					var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
					await InternalAPIs.CreateSessionAsync(requestInfo, accessToken).ConfigureAwait(false);

					// response
					json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
				}

				// response
				await Task.WhenAll(
					context.WriteResponseAsync(json),
					Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "End process => Error occurred while signing-in session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Validate an OTP session
		static async Task ValidateOTPSessionAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// prepare
				var body = requestInfo.GetBodyExpando();
				if (body == null)
					throw new InvalidTokenException("OTP is invalid (empty)");

				var id = body.Get<string>("ID");
				var otp = body.Get<string>("OTP");
				var info = body.Get<string>("Info");

				if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(otp) || string.IsNullOrWhiteSpace(info))
					throw new InvalidTokenException("OTP is invalid (empty)");

				// decrypt
				try
				{
					id = Base.AspNet.Global.RSA.Decrypt(id);
					otp = Base.AspNet.Global.RSA.Decrypt(otp);
					info = Base.AspNet.Global.RSA.Decrypt(info);
				}
				catch (Exception ex)
				{
					throw new InvalidTokenException("OTP is invalid (cannot decrypt)", ex);
				}

				// call service to validate
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "OTP",
					Verb = "POST",
					Body = new JObject()
					{
						{ "ID", id.Encrypt(Base.AspNet.Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Base.AspNet.Global.EncryptionKey) },
						{ "Info", info.Encrypt(Base.AspNet.Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}).ConfigureAwait(false);

				// register new session
				await Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID).ConfigureAwait(false);

				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.SessionID = UtilityService.NewUID;
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
				await InternalAPIs.CreateSessionAsync(requestInfo, accessToken, true).ConfigureAwait(false);

				// response
				json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);

				// response
				await Task.WhenAll(
					context.WriteResponseAsync(json),
					Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "End process => Error occurred while validating OTP session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Sign a session out
		static async Task SignSessionOutAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
					throw new InvalidRequestException();

				// call service to perform sign out
				await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "DELETE", requestInfo.Query, requestInfo.Header, null, new Dictionary<string, string>()
				{
					{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
				}, requestInfo.CorrelationID)).ConfigureAwait(false);

				// remove cache and send update message
				await Task.WhenAll(
					Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID),
					requestInfo.Session.SendOnlineStatusAsync(false)
				).ConfigureAwait(false);

				// create a new session
				requestInfo.Session.SessionID = UtilityService.NewUID;
				requestInfo.Session.User = new User();

				// register the new session of visitor
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
				var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken);
				await Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180).ConfigureAwait(false);

				// response
				var json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);
				await context.WriteResponseAsync(json).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "End process => Error occurred while signing-out session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(HttpContext context, RequestInfo requestInfo)
		{
			// call service to activate
			var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID)).ConfigureAwait(false);

			// update user information & get access token
			requestInfo.Session.User = json.FromJson<User>();
			var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);

			// register the session
			var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken).ToString(Formatting.None);
			await Task.WhenAll(
				InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", session, new Dictionary<string, string>()
				{
					{ "Signature", session.GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
				}, requestInfo.CorrelationID),
				requestInfo.Session.SendOnlineStatusAsync(true),
				Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session, 180)
			).ConfigureAwait(false);

			// response
			json = new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			requestInfo.Session.UpdateSessionJson(json, accessToken);
			await context.WriteResponseAsync(json).ConfigureAwait(false);
		}
		#endregion

		#region Create a session
		static JObject GenerateSessionJson(RequestInfo requestInfo, string accessToken = null, bool is2FAVerified = false, bool isOnline = true)
		{
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(60) },
				{ "UserID", requestInfo.Session.User.ID },
				{ "AccessToken", accessToken ?? User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey) },
				{ "IP", requestInfo.Session.IP },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "OSInfo", requestInfo.Header.ContainsKey("user-agent") ? requestInfo.Header["user-agent"].GetOSInfo() + " [" + requestInfo.Header["user-agent"] + "]" : "Unknown" },
				{ "Verification", is2FAVerified },
				{ "Online", isOnline }
			};
		}

		static async Task CreateSessionAsync(RequestInfo requestInfo, string accessToken = null, bool is2FAVerified = false)
		{
			var body = InternalAPIs.GenerateSessionJson(requestInfo, accessToken, is2FAVerified).ToString(Formatting.None);
			await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Base.AspNet.Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}).ConfigureAwait(false);

			await Task.WhenAll(
				Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, body, 180),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);
		}
		#endregion

		#region Verify a session
		internal static async Task<bool> CheckSessionExistAsync(Session session)
		{
			// pre-check
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				return false;
			else if (await Global.Cache.ExistsAsync("Session#" + session.SessionID).ConfigureAwait(false))
				return true;

			// check with user service
			var result = await InternalAPIs.CallServiceAsync(session, "Users", "Session", "GET", null, new Dictionary<string, string>()
			{
				{ "Exist", "" }
			}).ConfigureAwait(false);
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
			var cached = await Global.Cache.GetAsync<string>("Session#" + session.SessionID).ConfigureAwait(false);
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
				await InternalAPIs.CallServiceAsync(session, "Users", "Session", "GET", null, new Dictionary<string, string>()
				{
					{ "Verify", "" },
					{ "AccessToken", accessToken.Encrypt(Base.AspNet.Global.EncryptionKey) }
				}).ConfigureAwait(false);
		}
		#endregion

		#region Update sessions
		internal static async Task RequestUpdateSessionsAsync(RequestInfo requestInfo)
		{
			// check
			var userID = requestInfo.GetObjectIdentity();
			if (string.IsNullOrWhiteSpace(userID) || !userID.IsValidUUID())
				return;

			// get user information
			var user = (await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Account")
			{
				Query = requestInfo.Query,
				CorrelationID = requestInfo.CorrelationID
			}).ConfigureAwait(false)).FromJson<User>();

			// send inter-communicate message to tell services update old sessions with new access token
			await Global.SendInterCommunicateMessageAsync(new CommunicateMessage("Users")
			{
				Type = "Session",
				Data = new JObject()
				{
					{ "UserID", user.ID },
					{ "AccessToken", User.GetAccessToken(user, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey).Encrypt(Base.AspNet.Global.EncryptionKey) }
				}
			}).ConfigureAwait(false);
		}
		#endregion

		#region Helper: call service
		internal static Task<JObject> CallServiceAsync(RequestInfo requestInfo, string objectLogName = "Internal")
		{
			var name = $"net.vieapps.services.{requestInfo?.ServiceName}".ToLower();
			return Base.AspNet.Global.CallServiceAsync(requestInfo, Base.AspNet.Global.CancellationTokenSource.Token,
				(info) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Call the service [{name}]\r\n{info?.ToJson().ToString(Formatting.Indented)}");
				},
				(info, json) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Results from the service [{name}]\r\n{json?.ToString(Formatting.Indented)}");
				},
				(info, ex) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Error occurred while calling the service [{name}]", ex);
				}
			);
		}

		internal static Task<JObject> CallServiceAsync(Session session, string serviceName, string objectName, string verb = "GET", string body = null, Dictionary<string, string> extra = null, string correlationID = null)
		{
			return InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb)
			{
				Body = body ?? "",
				Extra = new Dictionary<string, string>(extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
				CorrelationID = correlationID ?? Base.AspNet.Global.GetCorrelationID()
			});
		}
		#endregion

		#region Helper: working with response JSON, online status, ...
		internal static void UpdateSessionJson(this Session session, JObject json, string accessToken)
		{
			json["ID"] = session.SessionID.Encrypt(Base.AspNet.Global.EncryptionKey.Reverse(), true);
			json.Add(new JProperty("Keys", new JObject()
			{
				{
					"RSA",
					new JObject()
					{
						{ "Exponent", Base.AspNet.Global.RSAExponent },
						{ "Modulus", Base.AspNet.Global.RSAModulus }
					}
				},
				{
					"AES",
					new JObject()
					{
						{ "Key", Base.AspNet.Global.GenerateEncryptionKey(session.SessionID).ToHexa() },
						{ "IV", Base.AspNet.Global.GenerateEncryptionIV(session.SessionID).ToHexa() }
					}
				},
				{
					"JWT",
					Base.AspNet.Global.JWTKey
				}
			}));
			json.Add(new JProperty("JWT", session.GetJSONWebToken(accessToken)));
		}

		//internal static async Task SendOnlineStatusAsync(this Session session, bool isOnline)
		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
		{
			return session.User == null || session.User.ID.Equals("") || session.User.IsSystemAccount
				? Task.CompletedTask
				: Global.SendInterCommunicateMessageAsync(new CommunicateMessage("Users")
				{
					Type = "OnlineStatus",
					Data = new JObject()
					{
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
			context.Response.StatusCode = 200;
			await context.Response.Output.WriteAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)).ConfigureAwait(false);
		}
		#endregion

	}
}
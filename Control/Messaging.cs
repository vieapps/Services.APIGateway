#region Related components
using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class MessagingService : IMessagingService
	{
		public async Task SendEmailAsync(EmailMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			message.From = string.IsNullOrWhiteSpace(message.From) ? MailSender.EmailDefaultSender : message.From;
			if (string.IsNullOrWhiteSpace(message.SmtpServer))
			{
				message.SmtpServer = MailSender.EmailSmtpServer;
				message.SmtpServerPort = MailSender.EmailSmtpServerPort;
				message.SmtpServerEnableSsl = MailSender.EmailSmtpServerEnableSsl;
				message.SmtpUsername = MailSender.EmailSmtpUser;
				message.SmtpPassword = MailSender.EmailSmtpUserPassword;
			}
			await EmailMessage.SaveAsync(message, MailSender.EmailsPath).ConfigureAwait(false);
		}

		public Task SendWebHookAsync(WebHookMessage message, CancellationToken cancellationToken = default(CancellationToken))
			=> WebHookMessage.SaveAsync(message, WebHookSender.WebHooksPath);
	}

	// -----------------------------------------------------------

	internal class MailSender : IDisposable
	{
		CancellationTokenSource CancellationTokenSource { get; }

		public MailSender(CancellationToken cancellationToken = default(CancellationToken))
			=> this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

		public void Dispose() => this.CancellationTokenSource.Cancel();

		~MailSender()
		{
			this.Dispose();
			this.CancellationTokenSource.Dispose();
		}

		#region Information
		static Dictionary<string, MailInfo> Messages = null;
		static string _EmailsPath = null, _EmailSmtpServer = null, _EmailSmtpServerEnableSsl = null, _EmailSmtpUser = null, _EmailSmtpUserPassword = null, _EmailDefaultSender = null;

		static int? _EmailSmtpServerPort = 0;

		internal static string EmailsPath => MailSender._EmailsPath ?? (MailSender._EmailsPath = Global.GetPath("Path:Emails", "emails"));

		internal static string EmailSmtpServer => MailSender._EmailSmtpServer ?? (MailSender._EmailSmtpServer = UtilityService.GetAppSetting("Email:SmtpServer", "localhost"));

		internal static int EmailSmtpServerPort => (MailSender._EmailSmtpServerPort ?? (MailSender._EmailSmtpServerPort = UtilityService.GetAppSetting("Email:SmtpServerPort", "25").CastAs<int?>())).Value;

		internal static string EmailSmtpUser => MailSender._EmailSmtpUser ?? (MailSender._EmailSmtpUser = UtilityService.GetAppSetting("Email:SmtpUser", ""));

		internal static string EmailSmtpUserPassword => MailSender._EmailSmtpUserPassword ?? (MailSender._EmailSmtpUserPassword = UtilityService.GetAppSetting("Email:SmtpUserPassword", ""));

		internal static bool EmailSmtpServerEnableSsl => (MailSender._EmailSmtpServerEnableSsl ?? (MailSender._EmailSmtpServerEnableSsl = UtilityService.GetAppSetting("Email:SmtpServerEnableSsl", "false"))).IsEquals("true");

		internal static string EmailDefaultSender => MailSender._EmailDefaultSender ?? (MailSender._EmailDefaultSender = UtilityService.GetAppSetting("Email:DefaultSender", "VIEApps.net <vieapps.net@gmail.com>"));

		public class MailInfo
		{
			public MailInfo()
			{
				this.Message = null;
				this.Time = DateTime.Now;
				this.Counters = 0;
			}

			public EmailMessage Message { get; set; }
			public DateTime Time { get; set; }
			public int Counters { get; set; }
		}
		#endregion

		#region Load & Save messages
		internal static void LoadMessages()
		{
			MailSender.Messages = MailSender.Messages ?? new Dictionary<string, MailInfo>();

			// previous messages
			var filePath = Path.Combine(Global.StatusPath, "mails.json");
			if (File.Exists(filePath))
				try
				{
					var msgs = JArray.Parse(UtilityService.ReadTextFile(filePath));
					File.Delete(filePath);

					foreach (JObject msg in msgs)
					{
						var message = new EmailMessage(msg.Get<string>("Message"));
						var time = msg.Get<DateTime>("Time");
						var counters = msg.Get<long>("Counters").CastAs<int>();
						MailSender.Messages.Add(message.ID, new MailInfo { Message = message, Time = time, Counters = counters });
					}
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while loading email messages: {ex.Message}", ex);
				}

			// new messages
			if (Directory.Exists(MailSender.EmailsPath))
				UtilityService.GetFiles(MailSender.EmailsPath, "*.msg")
					.ForEach(file =>
					{
						try
						{
							var msg = EmailMessage.Load(file.FullName);
							MailSender.Messages.Add(msg.ID, new MailInfo { Message = msg, Time = msg.SendingTime, Counters = 0 });
						}
						catch (Exception ex)
						{
							Global.OnError?.Invoke($"Error occurred while loading email messages: {ex.Message}", ex);
						}
						file.Delete();
					});
		}

		internal static void SaveMessages()
		{
			if (MailSender.Messages != null && MailSender.Messages.Count > 0)
				UtilityService.WriteTextFile(Path.Combine(Global.StatusPath, "mails.json"), MailSender.Messages.ToJArray(info => new JObject
				{
					{ "Time", info.Time },
					{ "Counters", info.Counters },
					{ "Message", info.Message.Encrypted }
				}).ToString(Formatting.Indented));
			MailSender.Messages = null;
		}
		#endregion

		#region Send messages
		async Task SendMessageAsync(EmailMessage msg, int counter)
		{
			try
			{
				await Task.Delay(100 + (counter * 10), this.CancellationTokenSource.Token);
				await MessageService.SendMailAsync(msg.From, msg.ReplyTo, msg.To, msg.Cc, msg.Bcc, msg.Subject, msg.Body, msg.Attachment, msg.Priority, msg.IsHtmlFormat, Encoding.GetEncoding(msg.Encoding), msg.SmtpServer, msg.SmtpServerPort.ToString(), msg.SmtpUsername, msg.SmtpPassword, msg.SmtpServerEnableSsl, this.CancellationTokenSource.Token);
				MailSender.Messages.Remove(msg.ID);

				Global.OnSendEmailSuccess?.Invoke(
					"The email message has been sent" + "\r\n" +
					$"- ID: {msg.ID}" + "\r\n" +
					$"- From: {msg.From}" + "\r\n" +
					$"- To: {msg.To}" + (!msg.Cc.Equals("") ? " / " + msg.Cc : "") + (!msg.Bcc.Equals("") ? " / " + msg.Bcc : "") + "\r\n" +
					$"- Subject: {msg.Subject}"
				);
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				var log =
					"Error occurred while sending an email message" + "\r\n" +
					$"- ID: {msg.ID}" + "\r\n" +
					$"- From: {msg.From}" + "\r\n" +
					$"- To: {msg.To}" + (!msg.Cc.Equals("") ? " / " + msg.Cc : "") + (!msg.Bcc.Equals("") ? " / " + msg.Bcc : "") + "\r\n" +
					$"- Subject: {msg.Subject}" + "\r\n\r\n" +
					$"- Error: {ex.Message} [{ex.GetType()}" + "\r\n\r\n";

				var counters = MailSender.Messages[msg.ID].Counters;
				if (counters > 4)
				{
					MailSender.Messages.Remove(msg.ID);
					log += "- Status: Remove from queue because its failed too much times";
				}
				else
				{
					var time = DateTime.Now.AddMinutes(1);
					if (counters == 1)
						time = DateTime.Now.AddMinutes(3);
					else if (counters == 2)
						time = DateTime.Now.AddMinutes(13);
					else if (counters > 2)
						time = DateTime.Now.AddMinutes(23 + ((counters - 2) * 3));

					MailSender.Messages[msg.ID].Time = time;
					MailSender.Messages[msg.ID].Counters = counters + 1;

					log += $"- Status: Update queue to re-send {time.ToDTString()}";
				}

				Global.OnSendEmailFailure?.Invoke(log, ex);
			}
		}

		public async Task ProcessAsync()
		{
			// load messages
			MailSender.LoadMessages();

			// send messages
			await MailSender.Messages
				.Where(kvp => kvp.Value.Time <= DateTime.Now)
				.ForEachAsync((kvp, index, cancellationToken) => this.SendMessageAsync(kvp.Value.Message, index))
				.ConfigureAwait(false);
		}
		#endregion

	}

	// -----------------------------------------------------------

	internal class WebHookSender : IDisposable
	{
		CancellationTokenSource CancellationTokenSource { get; }

		public WebHookSender(CancellationToken cancellationToken = default(CancellationToken))
			=> this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

		public void Dispose() => this.CancellationTokenSource.Cancel();

		~WebHookSender()
		{
			this.Dispose();
			this.CancellationTokenSource.Dispose();
		}

		#region Information
		static Dictionary<string, WebHookInfo> Messages = null;
		static string _WebHooksPath = null;
		internal static string WebHooksPath => WebHookSender._WebHooksPath ?? (WebHookSender._WebHooksPath = Global.GetPath("Path:WebHooks", "webhooks"));

		public class WebHookInfo
		{
			public WebHookInfo()
			{
				this.Message = null;
				this.Time = DateTime.Now;
				this.Counters = 0;
			}

			public WebHookMessage Message { get; set; }
			public DateTime Time { get; set; }
			public int Counters { get; set; }
		}
		#endregion

		#region Load & Save messages
		internal static async Task LoadMessagesAsync()
		{
			WebHookSender.Messages = WebHookSender.Messages ?? new Dictionary<string, WebHookInfo>();

			// previous messages
			var filePath = Path.Combine(Global.StatusPath, "webhooks.json");
			if (File.Exists(filePath))
				try
				{
					var msgs = JArray.Parse(await UtilityService.ReadTextFileAsync(filePath).ConfigureAwait(false));
					File.Delete(filePath);

					foreach (JObject msg in msgs)
					{
						var message = new WebHookMessage(msg.Get<string>("Message"));
						var time = msg.Get<DateTime>("Time");
						var counters = msg.Get<long>("Counters").CastAs<int>();
						WebHookSender.Messages.Add(message.ID, new WebHookInfo { Message = message, Time = time, Counters = counters });
					}
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while loading web-hook messages: {ex.Message}", ex);
				}

			// new messages
			if (Directory.Exists(WebHookSender.WebHooksPath))
				await UtilityService.GetFiles(WebHookSender.WebHooksPath, "*.msg")
					.ForEachAsync(async (file, token) =>
					{
						try
						{
							var msg = await WebHookMessage.LoadAsync(file.FullName).ConfigureAwait(false);
							WebHookSender.Messages.Add(msg.ID, new WebHookInfo { Message = msg, Time = msg.SendingTime, Counters = 0 });
						}
						catch (Exception ex)
						{
							Global.OnError?.Invoke($"Error occurred while loading web-hook messages: {ex.Message}", ex);
						}
						file.Delete();
					}, CancellationToken.None, true, false);
		}

		internal static void SaveMessages()
		{
			if (WebHookSender.Messages != null && WebHookSender.Messages.Count > 0)
				UtilityService.WriteTextFile(Path.Combine(Global.StatusPath, "webhooks.json"), WebHookSender.Messages.ToJArray(info => new JObject()
				{
					{ "Time", info.Time },
					{ "Counters", info.Counters },
					{ "Message", info.Message.Encrypted }
				}).ToString(Formatting.Indented));
			WebHookSender.Messages = null;
		}
		#endregion

		#region Send messages
		async Task SendMessageAsync(WebHookMessage msg, Action<string> onSuccess = null, Action<string, Exception> onError = null)
		{
			try
			{
				var query = string.Join("&", msg.Query.Select(info => info.Key + "=" + info.Value.UrlEncode()));
				await UtilityService.GetWebResponseAsync("POST", msg.EndpointURL + (!query.Equals("") ? "?" + query : ""), msg.Header, null, msg.Body, "application/json", 45, UtilityService.DesktopUserAgent + " VIEApps NGX WebHook Sender", null, null, null, this.CancellationTokenSource.Token);
				WebHookSender.Messages.Remove(msg.ID);

				Global.OnSendWebHookSuccess?.Invoke(
					"The web-hook message has been sent" + "\r\n" +
					$"- ID: {msg.ID}" + "\r\n" +
					$"- End-point: {msg.EndpointURL}"
				);
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				var log =
					"Error occurred while sending a web-hook message" + "\r\n" +
					$"- ID: {msg.ID}" + "\r\n" +
					$"- End-point: {msg.EndpointURL}" + "\r\n\r\n";

				var counters = WebHookSender.Messages[msg.ID].Counters;
				if (counters > 4)
				{
					WebHookSender.Messages.Remove(msg.ID);
					log += "- Status: Remove from queue because its failed too much times";
				}
				else
				{
					var time = DateTime.Now.AddMinutes(1);
					if (counters == 1)
						time = DateTime.Now.AddMinutes(3);
					else if (counters == 2)
						time = DateTime.Now.AddMinutes(13);
					else if (counters > 2)
						time = DateTime.Now.AddMinutes(23 + ((counters - 2) * 3));

					WebHookSender.Messages[msg.ID].Time = time;
					WebHookSender.Messages[msg.ID].Counters = counters + 1;

					log += $"- Status: Update queue to re-send {time.ToDTString()}";
				}

				Global.OnSendWebHookFailure?.Invoke(log, ex);
			}
		}

		public async Task ProcessAsync()
		{
			// load messages
			await WebHookSender.LoadMessagesAsync().ConfigureAwait(false);

			// send messages
			await WebHookSender.Messages
				.Where(kvp => kvp.Value.Time <= DateTime.Now)
				.ForEachAsync((kvp, cancellationToken) => this.SendMessageAsync(kvp.Value.Message))
				.ConfigureAwait(false);
		}
		#endregion

	}
}
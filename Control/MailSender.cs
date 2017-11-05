﻿#region Related components
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using System.IO;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class MailSender
	{
		public MailSender() { }

		#region Information
		static Dictionary<string, MailInfo> Messages = null;

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
			var filePath = Global.StatusPath + @"\mails.json";
			if (File.Exists(filePath))
				try
				{
					var msgs = JArray.Parse(UtilityService.ReadTextFile(filePath));
					File.Delete(filePath);

					foreach (JObject msg in msgs)
					{
						var message = new EmailMessage((msg["Message"] as JValue).Value as string);
						var time = (DateTime)(msg["Time"] as JValue).Value;
						var counters = (msg["Counters"] as JValue).Value.CastAs<int>();
						MailSender.Messages.Add(message.ID, new MailInfo() { Message = message, Time = time, Counters = counters });
					}
				}
				catch { }

			// new messages
			if (Directory.Exists(Global.EmailsPath))
				UtilityService.GetFiles(Global.EmailsPath, "*.msg")
					.ForEach(file =>
					{
						try
						{
							var msg = EmailMessage.Load(file.FullName);
							MailSender.Messages.Add(msg.ID, new MailInfo() { Message = msg, Time = msg.SendingTime, Counters = 0 });
						}
						catch { }
						file.Delete();
					});
		}

		internal static void SaveMessages()
		{
			if (MailSender.Messages != null && MailSender.Messages.Count > 0)
				UtilityService.WriteTextFile(Global.StatusPath + @"\mails.json", MailSender.Messages.ToJArray(info => new JObject()
				{
					{ "Time", info.Time },
					{ "Counters", info.Counters },
					{ "Message", info.Message.Encrypted }
				}).ToString(Formatting.Indented));
			MailSender.Messages = null;
		}
		#endregion

		#region Send a message
		async Task SendMessageAsync(EmailMessage msg, int counter, Action<string> onSuccess = null, Action<string, Exception> onError = null)
		{
			try
			{
				await Task.Delay(100 + (counter * 10), Global.CancellationTokenSource.Token);
				await MessageUtility.SendMailAsync(msg.From, msg.ReplyTo, msg.To, msg.Cc, msg.Bcc, msg.Subject, msg.Body, msg.Attachment, msg.Priority, msg.IsHtmlFormat, Encoding.GetEncoding(msg.Encoding), msg.SmtpServer, msg.SmtpServerPort.ToString(), msg.SmtpUsername, msg.SmtpPassword, msg.SmtpServerEnableSsl, Global.CancellationTokenSource.Token);
				onSuccess?.Invoke(msg.ID);
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				onError?.Invoke(msg.ID, ex);
			}
		}

		void OnSuccess(string id)
		{
			var msg = MailSender.Messages[id].Message;
			Global.WriteLog("The email has been sent" + "\r\n"
				+ "- ID: " + msg.ID + "\r\n"
				+ "- From: " + msg.From + "\r\n"
				+ "- To: " + msg.To + (!msg.Cc.Equals("") ? " / " + msg.Cc : "") + (!msg.Bcc.Equals("") ? " / " + msg.Bcc : "") + "\r\n"
				+ "- Subject: " + msg.Subject, null, true, null, "mail");
			MailSender.Messages.Remove(id);
		}

		void OnError(string id, Exception ex)
		{
			var msg = MailSender.Messages[id].Message;
			var log = "Error occurred while sending an email message" + "\r\n"
				+ "- ID: " + msg.ID + "\r\n"
				+ "- From: " + msg.From + "\r\n"
				+ "- To: " + msg.To + (!msg.Cc.Equals("") ? " / " + msg.Cc : "") + (!msg.Bcc.Equals("") ? " / " + msg.Bcc : "") + "\r\n"
				+ "- Subject: " + msg.Subject + "\r\n\r\n"
				+ "- Error: " + ex.Message + " [" + ex.GetType().ToString() + "]" + "\r\n\r\n";
			
			var counters = MailSender.Messages[id].Counters;
			if (counters > 4)
			{
				MailSender.Messages.Remove(id);
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

				MailSender.Messages[id].Time = time;
				MailSender.Messages[id].Counters = counters + 1;

				log += "- Status: Update queue to re-send at [" + time.ToDTString() + "]";
			}

			Global.WriteLog(log, ex, true, null, "mail");
		}
		#endregion

		public async Task ProcessAsync()
		{
			// load messages
			MailSender.LoadMessages();

			// send messages
			await MailSender.Messages
				.Where(kvp => kvp.Value.Time <= DateTime.Now)
				.ForEachAsync((kvp, index, cancellationToken) => this.SendMessageAsync(kvp.Value.Message, index, this.OnSuccess, this.OnError));
		}
	}
}

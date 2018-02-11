#region Related components
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class MessagingService : IMessagingService
	{
		public MessagingService() { }

		public async Task SendEmailAsync(EmailMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			// normalize
			message.From = string.IsNullOrWhiteSpace(message.From)
				? Global.EmailDefaultSender
				: message.From;

			if (string.IsNullOrWhiteSpace(message.SmtpServer))
			{
				message.SmtpServer = Global.EmailSmtpServer;
				message.SmtpServerPort = Global.EmailSmtpServerPort;
				message.SmtpServerEnableSsl = Global.EmailSmtpServerEnableSsl;
				message.SmtpUsername = Global.EmailSmtpUser;
				message.SmtpPassword = Global.EmailSmtpUserPassword;
			}

			// save into folder
			await EmailMessage.SaveAsync(message, Global.EmailsPath).ConfigureAwait(false);
		}

		public async Task SendWebHookAsync(WebHookMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			await WebHookMessage.SaveAsync(message, Global.WebHooksPath).ConfigureAwait(false);
		}
	}
}
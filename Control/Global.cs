#region Related components
using System;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;

using WampSharp.V2.Rpc;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public interface IServiceManager
	{
		/// <summary>
		/// Gets all available business services
		/// </summary>
		/// <returns></returns>
		[WampProcedure("net.vieapps.apigateway.controller.get")]
		Dictionary<string, string> GetAvailableBusinessServices();

		/// <summary>
		/// Checks to see a business service is running or not
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		[WampProcedure("net.vieapps.apigateway.controller.state")]
		bool IsBusinessServiceRunning(string name);

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="arguments"></param>
		[WampProcedure("net.vieapps.apigateway.controller.start")]
		void StartBusinessService(string name, string arguments = null);

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name"></param>
		[WampProcedure("net.vieapps.apigateway.controller.stop")]
		void StopBusinessService(string name);
	}

	//  --------------------------------------------------------

	public static class Global
	{
		/// <summary>
		/// Gets or sets the action to run when processing
		/// </summary>
		public static Action<string> OnProcess { get; set; } = (message) => { };

		/// <summary>
		/// Gets or sets the action to run when got an error
		/// </summary>
		public static Action<string, Exception> OnError { get; set; } = (message, exception) => { };

		/// <summary>
		/// Gets or sets the action to track
		/// </summary>
		public static Action<string, Exception> OnTrack { get; set; } = (message, exception) => { };

		/// <summary>
		/// Gets or sets the action to run when a email message has been sent successful
		/// </summary>
		public static Action<string> OnSendEmailSuccess { get; set; } = (message) => { };

		/// <summary>
		/// Gets or sets the action to run when a email message has been failure sending
		/// </summary>
		public static Action<string, Exception> OnSendEmailFailure { get; set; } = (message, exception) => { };

		/// <summary>
		/// Gets or sets the action to run when a web-hook message has been sent successful
		/// </summary>
		public static Action<string> OnSendWebHookSuccess { get; set; } = (message) => { };

		/// <summary>
		/// Gets or sets the action to run when a web-hook message has been failure sending
		/// </summary>
		public static Action<string, Exception> OnSendWebHookFailure { get; set; } = (message, exception) => { };

		/// <summary>
		/// Gets or sets the action to run when a collection of log messages has been updated
		/// </summary>
		public static Action<string, string> OnLogsUpdated { get; set; } = (serviceName, logs) => { };

		/// <summary>
		/// Gets or sets the action to run when a message has been sent successful
		/// </summary>
		public static Action<string> OnSendRTUMessageSuccess { get; set; } = (message) => { };

		/// <summary>
		/// Gets or sets the action to run when a message has been failure sending
		/// </summary>
		public static Action<string, Exception> OnSendRTUMessageFailure { get; set; } = (message, exception) => { };

		/// <summary>
		/// Gets or sets the action to run when a business is started
		/// </summary>
		public static Action<string, string> OnServiceStarted { get; set; } = (serviceName, message) => { };

		/// <summary>
		/// Gets or sets the action to run when a business is stopped
		/// </summary>
		public static Action<string, string> OnServiceStopped { get; set; } = (serviceName, message) => { };

		/// <summary>
		/// Gets or sets the action to run when the controller got a message from service (console data)
		/// </summary>
		public static Action<string, string> OnGotServiceMessage { get; set; } = (serviceName, message) => { };

		internal static string GetPath(string name, string folder, bool getDefaultIsNotFound = true)
		{
			var path = UtilityService.GetAppSetting(name);
			if (string.IsNullOrWhiteSpace(path) && getDefaultIsNotFound)
				path = Path.Combine(Directory.GetCurrentDirectory(), folder);
			else if (!string.IsNullOrWhiteSpace(path) && path.EndsWith(Path.DirectorySeparatorChar.ToString()))
				path = path.Left(path.Length - 1);
			return path;
		}

		static string _StatusPath = null;

		internal static string StatusPath => Global._StatusPath ?? (Global._StatusPath = Global.GetPath("Path:Status", "status"));

	}
}

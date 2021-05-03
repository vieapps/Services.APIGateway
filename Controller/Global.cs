#region Related components
using System;
using System.IO;
using System.Collections.Generic;
using WampSharp.V2.Rpc;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.APIGateway
{
	/// <summary>
	/// Presents a service controller
	/// </summary>
	public interface IController
	{
		/// <summary>
		/// Gets all available business services
		/// </summary>
		/// <returns></returns>
		[WampProcedure("services.apigateway.controller.{0}.get.available.business.services")]
		Dictionary<string, string> GetAvailableBusinessServices();

		/// <summary>
		/// Checks to see a business service is available or not
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		[WampProcedure("services.apigateway.controller.{0}.is.business.service.available")]
		bool IsBusinessServiceAvailable(string name);

		/// <summary>
		/// Checks to see a business service is running or not
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		[WampProcedure("services.apigateway.controller.{0}.is.business.service.running")]
		bool IsBusinessServiceRunning(string name);

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="arguments"></param>
		[WampProcedure("services.apigateway.controller.{0}.start.business.service")]
		void StartBusinessService(string name, string arguments = null);

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name"></param>
		[WampProcedure("services.apigateway.controller.{0}.stop.business.service")]
		void StopBusinessService(string name);
	}

	//  --------------------------------------------------------

	/// <summary>
	/// Presents a service manager
	/// </summary>
	public interface IManager
	{
		/// <summary>
		/// Gets all available service controllers
		/// </summary>
		/// <returns></returns>
		[WampProcedure("services.apigateway.manager.get.available.controllers")]
		JArray GetAvailableControllers();

		/// <summary>
		/// Gets all available business services
		/// </summary>
		/// <returns></returns>
		[WampProcedure("services.apigateway.manager.get.available.services")]
		JArray GetAvailableServices();
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

		static string _StatusPath = null, _TempPath = null;

		internal static string StatusPath => Global._StatusPath ?? (Global._StatusPath = Global.GetPath("Path:Status", "status"));

		internal static string TempPath => Global._TempPath ?? (Global._TempPath = Global.GetPath("Path:Temp", "temp"));
	}

	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class { }
}

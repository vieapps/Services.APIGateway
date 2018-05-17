﻿#region Related components
using System;
using System.IO;
using System.Linq;
using System.Xml;
using System.Threading;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
    public class HostComponent
    {
		IServiceComponent ServiceComponent { get; set; }

		public void Start(string[] args)
		{
			// prepare
			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var apiCallToStop = apiCall != null && apiCall.IsEquals("/agc:s");
			var isUserInteractive = Environment.UserInteractive && apiCall == null;
			if (isUserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

			// prepare type name
			var typeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			var configFilename = $"VIEApps.Services.APIGateway.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "exe" : "dll")}.config";
			if (string.IsNullOrWhiteSpace(typeName) && File.Exists(configFilename) && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
				try
				{
					var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
					var xml = new XmlDocument();
					xml.LoadXml(UtilityService.ReadTextFile(configFilename));
					typeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "").Replace(StringComparison.OrdinalIgnoreCase, ",x86", "");
				}
				catch { }

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(typeName))
			{
				if (isUserInteractive)
				{
					Console.WriteLine($"VIEApps NGX API Gateway - Service Hoster v{Assembly.GetExecutingAssembly().GetVersion()}");
					Console.WriteLine("");
					Console.WriteLine("Syntax: VIEApps.Services.APIGateway.Host /svc:<service-component-namespace,service-assembly>");
					Console.WriteLine("");
					Console.WriteLine("Ex.: VIEApps.Services.APIGateway.Host /svc:net.vieapps.Services.Systems.ServiceComponent,VIEApps.Services.Systems");
					Console.WriteLine("");
					Console.ReadLine();
				}
				else
					Console.WriteLine("No matched type name is found");
				return;
			}

			// initialize the instance of service component
			var serviceType = Type.GetType(typeName);
			if (serviceType == null)
			{
				Console.WriteLine($"The type of the service component is not found [{typeName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			this.ServiceComponent = serviceType.CreateInstance() as IServiceComponent;
			if (this.ServiceComponent == null || !(this.ServiceComponent is IService))
			{
				Console.WriteLine($"The type of the service component is invalid [{serviceType.GetTypeName()}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Newtonsoft.Json.Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare logging
#if DEBUG
			var logLevel = LogLevel.Debug;
#else
			var logLevel = LogLevel.Information;
			try
			{
				logLevel = UtilityService.GetAppSetting("Logs:Level", "Information").ToEnum<LogLevel>();
			}
			catch { }
#endif

			Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>());

			var path = UtilityService.GetAppSetting("Path:Logs");
			if (Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}_" + (this.ServiceComponent as IService).ServiceName.ToLower() + ".txt");
				Logger.GetLoggerFactory().AddFile(path, logLevel);
			}

			if (isUserInteractive)
				Logger.GetLoggerFactory().AddConsole(logLevel);

			var logger = this.ServiceComponent.Logger = Logger.GetLoggerFactory().CreateLogger(this.ServiceComponent.GetType());

			// prepare the signal to start/stop when the service was called from API Gateway
			var uri = (this.ServiceComponent as IService).ServiceURI;
			EventWaitHandle waitHandle = null;
			if (!isUserInteractive)
			{
				// get the flag of the existing instance
				waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, uri, out bool createdNew);

				// process the call to stop
				if (apiCallToStop)
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						waitHandle.Set();

					// then exit
					waitHandle.Dispose();
					this.ServiceComponent.Dispose();
					return;
				}
			}

			// start the service component
			logger.LogInformation($"The service [{uri}] is starting...");
			this.ServiceComponent.Start(args, "false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true);

			// assign the static instance of the service component
			ServiceBase.ServiceComponent = this.ServiceComponent as ServiceBase;
			logger.LogInformation($"The service [{uri}] is started. PID: {Process.GetCurrentProcess().Id}");

			// wait for exit signal
			if (isUserInteractive)
			{
				logger.LogInformation($"=====> Press RETURN to terminate...");
				Console.ReadLine();
				this.Stop();
			}
			else
			{
				waitHandle.WaitOne();
				waitHandle.Dispose();
				this.Stop();
			}
		}

		public void Stop()
		{
			this.ServiceComponent?.Dispose();
		}
	}
}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace net.vieapps.Services.APIGateway
{
	[RunInstaller(true)]
	public partial class ServiceInstaller : Installer
	{
		public ServiceInstaller()
		{
			this.InitializeComponent();

			this.Installers.Add(new ServiceProcessInstaller
			{
				Account = ServiceAccount.LocalSystem,
				Username = null,
				Password = null
			});

			this.Installers.Add(new System.ServiceProcess.ServiceInstaller()
			{
				StartType = ServiceStartMode.Automatic,
				ServiceName = "VIEApps-APIGateway-Router",
				DisplayName = "VIEApps APIGateway Router",
				Description = "Router for serving RPC and Pub/Sub messages of all microservices in the VIEApps NGX - using Web Application Messaging Protocol (WAMP)"
			});

			this.AfterInstall += (sender, args) =>
			{
				try
				{
					using (var serviceController = new ServiceController("VIEApps-APIGateway-Router"))
					{
						serviceController.Start();
					}
				}
				catch { }
			};
		}
	}
}
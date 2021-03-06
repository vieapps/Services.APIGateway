using System;
using System.ServiceProcess;
namespace net.vieapps.Services.APIGateway
{
	[System.ComponentModel.RunInstaller(true)]
	public partial class ServiceInstaller : System.Configuration.Install.Installer
	{
		public ServiceInstaller()
		{
			this.InitializeComponent();

			this.Installers.Add(new ServiceProcessInstaller()
			{
				Account = ServiceAccount.LocalSystem,
				Username = null,
				Password = null
			});

			this.Installers.Add(new System.ServiceProcess.ServiceInstaller()
			{
				StartType = ServiceStartMode.Automatic,
				ServiceName = "VIEApps-APIGateway-Watcher",
				DisplayName = "VIEApps API Gateway Watcher",
				Description = "The Night Watch of VIEApps NGX API Gateway & all microservices"
			});

			this.AfterInstall += (sender, args) =>
			{
				try
				{
					using (var serviceController = new ServiceController("VIEApps-APIGateway-Watcher"))
					{
						serviceController.Start();
					}
				}
				catch { }
			};
		}
	}
}
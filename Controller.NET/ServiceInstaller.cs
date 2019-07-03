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
				ServiceName = "VIEApps-APIGateway-Controller",
				DisplayName = "VIEApps API Gateway Controller",
				Description = "Controller for managing all microservices in the VIEApps NGX"
			});

			this.AfterInstall += (sender, args) =>
			{
				try
				{
					using (var serviceController = new ServiceController("VIEApps-APIGateway-Controller"))
					{
						serviceController.Start();
					}
				}
				catch { }
			};
		}
	}
}
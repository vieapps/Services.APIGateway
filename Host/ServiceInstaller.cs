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

			this.Installers.Add(new ServiceProcessInstaller()
			{
				Account = ServiceAccount.LocalSystem,
				Username = null,
				Password = null
			});

			this.Installers.Add(new System.ServiceProcess.ServiceInstaller()
			{
				StartType = ServiceStartMode.Automatic,
				ServiceName = "VIEApps-API-Gateway",
				DisplayName = "VIEApps API Gateway",
				Description = "Gateway for routing requests of all microservices in the VIEApps NGX"
			});

			this.AfterInstall += new InstallEventHandler(this.StartServiceAfterInstall);
		}

		void StartServiceAfterInstall(object sender, InstallEventArgs args)
		{
			try
			{
				using (var controller = new ServiceController("VIEApps-API-Gateway"))
				{
					controller.Start();
				}
			}
			catch { }
		}
	}
}
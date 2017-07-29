using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.Threading.Tasks;

namespace net.vieapps.Services.APIGateway
{
	[RunInstaller(true)]
	public partial class ServiceInstaller : Installer
	{
		public ServiceInstaller()
		{
			this.InitializeComponent();
		}
	}
}

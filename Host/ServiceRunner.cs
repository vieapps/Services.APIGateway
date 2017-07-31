using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace net.vieapps.Services.APIGateway
{
	partial class ServiceRunner : ServiceBase
	{
		public ServiceRunner()
		{
			this.InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			Global.InitializeLog();
			Global.Component.Start(args);
		}

		protected override void OnStop()
		{
			Global.Component.Dispose();
			Global.DisposeLog();
		}
	}
}

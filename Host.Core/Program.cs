using System;
using System.IO;
using net.vieapps.Components.Utility;
namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHostingBase
	{
		protected override void PrepareServiceType()
		{
			base.PrepareServiceType();
			this.ServiceType = this.ServiceType ?? AssemblyLoader.GetType(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll"), this.ServiceTypeName);
		}
	}
}
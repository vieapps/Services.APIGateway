using System;
namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHostingBase
	{
		protected override void PrepareServiceType(Action<ServiceHostingBase> onCompleted = null)
			=> base.PrepareServiceType(_ => this.ServiceType ??= Components.Utility.AssemblyLoader.GetType(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll"), this.ServiceTypeName));
	}
}
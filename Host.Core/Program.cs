using System.Linq;
namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHost
	{
		protected override void PrepareServiceType()
		{
			base.PrepareServiceType();
			if (this.ServiceType == null)
				this.ServiceType = new Components.Utility.AssemblyLoader(System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll")).Assembly.GetExportedTypes().FirstOrDefault(serviceType => this.ServiceTypeName.Equals(serviceType.ToString()));
		}
	}
}
using System.Linq;
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
			this.ServiceType = this.ServiceType ?? new Components.Utility.AssemblyLoader(System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll")).Assembly.GetExportedTypes().FirstOrDefault(serviceType => this.ServiceTypeName.Equals(serviceType.ToString()));
		}
	}
}
using System;
using System.IO;
using System.Linq;
using System.Runtime.Loader;
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
			{
				var serviceAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll"));
				serviceAssembly.GetReferencedAssemblies()
					.Where(n => n.Name.StartsWith("VIEApps.Services.") && !n.Name.StartsWith("VIEApps.Services.Base"))
					.ToList().ForEach(n => AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{n.Name}.dll")));
				this.ServiceType = serviceAssembly.GetExportedTypes().FirstOrDefault(serviceType => this.ServiceTypeName.Equals(serviceType.ToString()));
			}
		}
	}
}
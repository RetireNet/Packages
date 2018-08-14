using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace ContentTool
{
    class Program
    {
        static void Main(string[] args)
        {
            var jsonFile = new JsonFile 
            {
                Link = "https://github.com/aspnet/Announcements/issues/311",
                Description = "Microsoft Security Advisory ASPNETCore-July18: ASP.NET Core Denial Of Service Vulnerability"                
            };
            

            var r1 = new Recommendation("Microsoft.AspNetCore.Server.Kestrel.Core")
                .InsteadOf("2.0.0", "2.0.1", "2.0.2", "2.0.3").Prefer("2.0.4")
                .InsteadOf("2.1.0", "2.1.1").Prefer("2.1.2");

            var r2 = new Recommendation("Microsoft.AspNetCore.All")
                .InsteadOf("2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6", "2.0.7", "2.0.8").Prefer("2.0.9")
                .InsteadOf("2.1.0", "2.1.1").Prefer("2.1.2");

            var r3 = new Recommendation("Microsoft.AspNetCore.App")
                .InsteadOf("2.1.0", "2.1.1").Prefer("2.1.2");

            jsonFile.Packages.AddRange(r1.Packages);
            jsonFile.Packages.AddRange(r2.Packages);
            jsonFile.Packages.AddRange(r3.Packages);

            var serialized = JsonConvert.SerializeObject(jsonFile, new JsonSerializerSettings 
            { 
                Formatting = Formatting.Indented, 
                ContractResolver = new CamelCasePropertyNamesContractResolver() 
            });
            
            File.WriteAllText("./bin/output.json", serialized);
            Console.WriteLine("Done");
        }

        private static IEnumerable<Package> SameVersionRecommendation(string packageId)
        {
            var r = new Recommendation(packageId)
                .InsteadOf("4.0.0", "4.1.0", "4.1.1").Prefer("4.1.3")
                .InsteadOf("4.3.0", "4.3.1").Prefer("4.3.3")
                .InsteadOf("4.4.0", "4.4.1", "4.4.2").Prefer("4.4.4")
                .InsteadOf("4.5.0", "4.5.1").Prefer("4.5.3");
            return r.Packages;
        }
    }
    
    public class JsonFile 
    {
        public JsonFile()
        {
            Packages = new List<Package>();
        }

        public string Link { get; set; }
        public string Description { get; set; }
        public List<Package> Packages { get; }
        
    }

    public class Package 
    {
        public string Id { get; set; }
        public string Affected { get; set; }
        public string Fix { get; set; }        
    }

    public class Recommendation 
    {
        public string Id { get; }

        public Recommendation(string id)
        {
            Id = id;
            Packages = new List<Package>();
        }   

        public List<Package> Packages { get; }

        public InsteadOf InsteadOf(params string[] insteadOfs)
        {            
            return new InsteadOf(this, insteadOfs);
        }    
    }

    public class InsteadOf 
    {
        private Recommendation _r;
        private string[] _affected;

        public InsteadOf(Recommendation r, params string[] insteadOfs)
        {
            _r = r;
            _affected = insteadOfs;
        }

        public Recommendation Prefer(string fixVersion)
        {
            foreach(var a in _affected)
            {
                Console.WriteLine("Vulnerable " + _r.Id + "/" + a + ". Fix: " + fixVersion);
                _r.Packages.Add(new Package
                {
                    Id = _r.Id,
                    Affected = a,
                    Fix = fixVersion
                });
            }
            return _r;            
        }
    }
}

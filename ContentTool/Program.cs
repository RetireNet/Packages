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
                Link = "https://github.com/dotnet/announcements/issues/73",
                Description = "Microsoft Security Advisory CVE-2018-8356: .NET Core Security Feature Bypass Vulnerability"                
            };
            
            var r = new Recommendation("System.Private.ServiceModel")
                .InsteadOf("4.0.0", "4.1.0", "4.1.1").Prefer("4.1.3")
                .InsteadOf("4.3.0", "4.3.1").Prefer("4.3.3")
                .InsteadOf("4.4.0", "4.4.1", "4.4.2").Prefer("4.4.4");

            Console.WriteLine("Count: " + r.Packages.Count());

            jsonFile.Packages.AddRange(r.Packages);            

            var serialized = JsonConvert.SerializeObject(jsonFile, new JsonSerializerSettings 
            { 
                Formatting = Formatting.Indented, 
                ContractResolver = new CamelCasePropertyNamesContractResolver() 
            });
            
            File.WriteAllText("./bin/output.json", serialized);
            Console.WriteLine("Done");
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
        public List<Package> Packages {get;set; }
    }

    public class Package 
    {
        public string Id { get; set; }
        public string Affected { get; set; }
        public string Fix { get; set; }        
    }

    public class Recommendation 
    {
        public string Id { get; set; }

        public Recommendation(string id)
        {
            Id = id;
            Packages = new List<Package>();
        }   

        public List<Package> Packages { get;set;}

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

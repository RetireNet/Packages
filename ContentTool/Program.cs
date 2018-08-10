using System;
using System.Collections.Generic;
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
                Link = "some-url",
                Description = "Some-bad-thing"
            };

            var serialized = JsonConvert.SerializeObject(jsonFile, new JsonSerializerSettings 
            { 
                Formatting = Formatting.Indented, 
                ContractResolver = new CamelCasePropertyNamesContractResolver() 
            });
            
            File.WriteAllText("./output.json", serialized);
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
}

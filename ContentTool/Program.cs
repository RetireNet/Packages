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
            var jsonFile = args.Length != 0 
                ? HardCodedFiles.GetJuly18JsonFile()
                : InputParser.Read();

            var serialized = JsonConvert.SerializeObject(jsonFile, new JsonSerializerSettings 
            { 
                Formatting = Formatting.Indented, 
                ContractResolver = new CamelCasePropertyNamesContractResolver() 
            });
            
            File.WriteAllText(jsonFile.OutputFile ?? "./bin/output.json", serialized);
            Console.WriteLine("Done");
        }


    }
}

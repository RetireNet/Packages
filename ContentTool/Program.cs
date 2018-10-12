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
                ? HardCodedFiles.GetSept11JsonFile()
                : InputParser.Read();

            var serialized = JsonConvert.SerializeObject(jsonFile, new JsonSerializerSettings 
            { 
                Formatting = Formatting.Indented, 
                ContractResolver = new CamelCasePropertyNamesContractResolver() 
            });
            
            File.WriteAllText(jsonFile.OutputFile ?? "./output.json", serialized);
            Console.WriteLine("Done");
        }


    }
}

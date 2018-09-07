using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ContentTool
{
    internal class InputParser
    {
        public static JsonFile Read()
        {
            Console.WriteLine("Enter link to announcement:");
            var link = Console.ReadLine();
            Console.WriteLine("Enter description of announcement:");
            var description = Console.ReadLine();
            Console.WriteLine("File containging paste of table of vulnerabilities and fixes (excluding headers):");
            var filepath = Console.ReadLine();
            var content = File.ReadAllTextAsync(filepath).GetAwaiter().GetResult();
            Console.WriteLine("Output file:");
            var outputFile = Console.ReadLine();
      

            return new JsonFile
            {
                Link = link,
                Description = description,
                Packages = ParseTable(content).ToList(),
                OutputFile = outputFile
            };
        }

        private static IEnumerable<Package> ParseTable(string content)
        {
            var regex = new Regex("[A-Za-z]+(?:\\.[A-Za-z]+)+");

            var matches = regex.Matches(content);
            var stuff = content;
            foreach (Match match in matches.Reverse())
            {
                var id = match.Value;
                var vulnerableAndSecureCellsString = stuff.Substring(match.Index + match.Length);
                var vulnerableAndSecureCells = vulnerableAndSecureCellsString.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                var secureVersions = vulnerableAndSecureCells[1].Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var vulnerablePerSecure = vulnerableAndSecureCells[0].Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                if (vulnerablePerSecure.Length != secureVersions.Length)
                    throw new Exception("Could not match vulnerable versions to corresponding secure version");
                for (int i = 0; i < secureVersions.Length; i++)
                {
                    foreach (var vulnerable in vulnerablePerSecure[i].Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()))
                    {
                        yield return new Package {Id = id, Affected = vulnerable, Fix = secureVersions[i].Trim()};
                    }
                }
                stuff = stuff.Substring(0, match.Index);
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Text;

namespace ContentTool
{
    class HardCodedFiles
    {
        public static JsonFile GetJuly18JsonFile()
        {
            var jsonFile = new JsonFile
            {
                Link = "https://github.com/dotnet/announcements/issues/95",
                Description = "Microsoft Security Advisory CVE-2018-8416: .NET Core Tampering Vulnerability"
            };


            var r1 = new Recommendation("System.IO.Compression.ZipFile")
                .InsteadOf("4.0.0", "4.0.1", "4.3.0").Prefer("4.3.1");
            jsonFile.Packages.AddRange(r1.Packages);

            return jsonFile;
        }

            public static JsonFile GetSept11JsonFile()
        {
            var jsonFile = new JsonFile
            {
                Link = "https://github.com/dotnet/announcements/issues/95",
                Description = "Microsoft Security Advisory CVE-2018-8416: .NET Core Tampering Vulnerability"
            };



            var r2 = new Recommendation("Microsoft.AspNetCore.All")
                .InsteadOf("2.1.0", "2.1.1", "2.1.2", "2.1.3").Prefer("2.1.4");

            var r3 = new Recommendation("Microsoft.AspNetCore.App")
                .InsteadOf("2.1.0", "2.1.1", "2.1.2", "2.1.3").Prefer("2.1.4");

            jsonFile.Packages.AddRange(r2.Packages);
            jsonFile.Packages.AddRange(r3.Packages);
            return jsonFile;
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

        private class Recommendation
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

        private class InsteadOf
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
                foreach (var a in _affected)
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
}

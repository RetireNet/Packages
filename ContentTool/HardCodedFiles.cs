using System;
using System.Collections.Generic;
using System.Text;

namespace ContentTool
{
    class HardCodedFiles
    {
        public static JsonFile GetOctober2019()
        {
            var jsonFile = new JsonFile
            {
                Link = "https://github.com/aspnet/Announcements/issues/385",
                Description = "Microsoft Security Advisory CVE-2018-8269: Denial of Service Vulnerability in OData"
            };


            var r1 = new Recommendation("Microsoft.AspNetCore.All")
                .InsteadOf("2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9", "2.1.10", "2.1.11", "2.1.12").Prefer("2.1.13")
                .InsteadOf("2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6").Prefer("2.2.7");
            jsonFile.Packages.AddRange(r1.Packages);
            
            var r2 = new Recommendation("Microsoft.AspNetCore.DataProtection.AzureStorage")
                .InsteadOf("2.1.1").Prefer("2.1.2")
                .InsteadOf("2.2.0").Prefer("2.2.1");

            var r3 = new Recommendation("Microsoft.Data.OData")
                .InsteadOf("5.0.1", "5.0.2", "5.1.0", "5.2.0", "5.3.0", "5.4.0", "5.5.0", "5.6.0", "5.6.1", "5.6.2", "5.6.3", "5.6.4", "5.7.0").Prefer("5.8.4");
            
            jsonFile.Packages.AddRange(r2.Packages);
            jsonFile.Packages.AddRange(r3.Packages);
            return jsonFile;
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

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
                Link = "https://github.com/aspnet/Announcements/issues/384",
                Description = "Microsoft Security Advisory CVE-2019-1302: ASP.NET Core Elevation Of Privilege Vulnerability"
            };


            var r1 = new Recommendation("Microsoft.AspNetCore.SpaServices")
                .InsteadOf("2.1.0", "2.1.1").Prefer("2.1.2")
                .InsteadOf("2.2.0").Prefer("2.2.1");
            jsonFile.Packages.AddRange(r1.Packages);
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

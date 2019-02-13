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

        public static JsonFile GetFebruary2019()
        {
            var jsonFile = new JsonFile
            {
                Link = "https://github.com/dotnet/announcements/issues/97",
                Description = "Microsoft Security Advisory CVE-2019-0657: .NET Core Domain Spoofing Vulnerability"
            };



            var r1 = new Recommendation("System.Private.Uri")
                .InsteadOf("4.3.0").Prefer("4.3.1");

            var r2 = new Recommendation("Microsoft.NETCore.App")
                .InsteadOf("2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7").Prefer("2.1.8")
                .InsteadOf("2.2.0", "2.2.1").Prefer("2.2.2");
            
            jsonFile.Packages.AddRange(r1.Packages);
            jsonFile.Packages.AddRange(r2.Packages);
            return jsonFile;
        }

        public static JsonFile GetJanuar2019()
        {
            var jsonFile = new JsonFile
            {
                Link = "https://github.com/aspnet/Announcements/issues/334",
                Description = "Microsoft Security Advisory CVE-2019-0564: ASP.NET Core Denial of Service Vulnerability"
            };



            var r2 = new Recommendation("Microsoft.AspNetCore.WebSockets")
                .InsteadOf("2.1.0", "2.1.1").Prefer("2.1.7")
                .InsteadOf("2.2.0").Prefer("2.2.1");

            var r3 = new Recommendation("Microsoft.AspNetCore.Server.Kestrel.Core")
                .InsteadOf(	"2.1.0", "2.1.1", "2.1.2", "2.1.3").Prefer("2.1.7");
            
            var r4 = new Recommendation("System.Net.WebSockets.WebSocketProtocol")
                .InsteadOf(	"4.5.0", "4.5.1", "4.5.2").Prefer("4.5.3");

            var r5 = SameVersionRecommendation("Microsoft.NETCore.App");
            var r6 = SameVersionRecommendation("Microsoft.AspNetCore.App");
            var r7 = SameVersionRecommendation("Microsoft.AspNetCore.All");

            jsonFile.Packages.AddRange(r2.Packages);
            jsonFile.Packages.AddRange(r3.Packages);
            jsonFile.Packages.AddRange(r4.Packages);
            jsonFile.Packages.AddRange(r5);
            jsonFile.Packages.AddRange(r6);
            jsonFile.Packages.AddRange(r7);
            return jsonFile;
        }

        private static IEnumerable<Package> SameVersionRecommendation(string packageId)
        {
            var r = new Recommendation(packageId)
                .InsteadOf("2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6").Prefer("2.1.7")
                .InsteadOf("2.2.0").Prefer("2.2.1");
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

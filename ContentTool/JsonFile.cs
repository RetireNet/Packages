using System.Collections.Generic;

namespace ContentTool
{
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
}
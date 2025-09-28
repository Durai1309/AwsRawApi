using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace AwsRawApi.Controllers

{

    [ApiController]
    [Route("api/[controller]")]

    public class Ec2RawController : ControllerBase
    {
        public class RegionInfo
        {
            public string? Region { get; set; }
            public object Response { get; set; } = new { Instances = new object[0] };
        }

        [HttpGet("instances/all-regions")]
        public async Task<IActionResult> GetInstancesAllRegions([FromQuery] string accessKey, [FromQuery] string secretKey)
        {
            if (string.IsNullOrEmpty(accessKey) || string.IsNullOrEmpty(secretKey))
                return BadRequest("Please provide accessKey and secretKey");

            var regions = await GetAllRegionsAsync(accessKey, secretKey);
            var allResults = new List<RegionInfo>();

            foreach (var region in regions)
            {
                string service = "ec2";
                string host = $"ec2.{region}.amazonaws.com";
                string endpoint = $"https://{host}";
                string query = "Action=DescribeInstances&Version=2016-11-15";
                string url = $"{endpoint}/?{query}";

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                SignRequest(request, query, accessKey, secretKey, region, service, host);

                using var client = new HttpClient();
                try
                {

                    var response = await client.SendAsync(request);
                    var content = await response.Content.ReadAsStringAsync();
                    var parsed = ParseDescribeInstancesXml(content);
                    allResults.Add(new RegionInfo
                    {
                        Region = region,
                        Response = parsed
                    });
                }
                catch (Exception ex)
                {
                    allResults.Add(new RegionInfo
                    {
                        Region = region,
                        Response = new { error = ex.Message, Instances = new object[0] }
                    });
                }
            }
            return Ok(allResults);
        }

        private async Task<List<string>> GetAllRegionsAsync(string accessKey, string secretKey)
        {
            string service = "ec2";
            string region = "us-east-1";
            string host = $"ec2.{region}.amazonaws.com";
            string endpoint = $"https://{host}";
            string query = "Action=DescribeRegions&Version=2016-11-15";
            string url = $"{endpoint}/?{query}";

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            SignRequest(request, query, accessKey, secretKey, region, service, host);

            using var client = new HttpClient();
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();
            var regions = new List<string>();
            var xml = XDocument.Parse(content);
            var ns = xml.Root.GetDefaultNamespace();
            var items = xml.Descendants(ns + "item");
            foreach (var item in items)
            {
                var regionName = item.Element(ns + "regionName")?.Value;
                if (!string.IsNullOrEmpty(regionName))
                    regions.Add(regionName);
            }
            return regions;
        }

        private object ParseDescribeInstancesXml(string xmlString)
        {
            try
            {
                var doc = XDocument.Parse(xmlString);
                var ns = doc.Root.GetDefaultNamespace();
                var reservations = doc.Descendants(ns + "reservationSet")
                                      .Descendants(ns + "item");

                var instances = new List<Dictionary<string, object>>();

                foreach (var res in reservations)
                {
                    var instanceElements = res.Descendants(ns + "instancesSet").Descendants(ns + "item");
                    foreach (var inst in instanceElements)
                    {
                        var dict = new Dictionary<string, object>();

                        foreach (var el in inst.Elements())
                        {
                            if (el.HasElements)
                            {
                                dict[el.Name.LocalName] = el.Elements()

                                    .ToDictionary(

                                        ee => ee.Name.LocalName,

                                        ee => ee.HasElements ? ee.Elements().ToDictionary(x => x.Name.LocalName, x => (object)x.Value) : (object)ee.Value

                                    );
                            }
                            else
                            {
                                dict[el.Name.LocalName] = el.Value;
                            }
                        }
                        instances.Add(dict);
                    }
                }
                return new { Instances = instances };
            }
            catch (Exception ex)

            {
                return new { error = "Failed to parse XML", details = ex.Message, Instances = new object[0] };
            }

        }

        private void SignRequest(HttpRequestMessage request, string query, string accessKey, string secretKey, string region, string service, string host)
        {
            var t = DateTime.UtcNow;
            string amzDate = t.ToString("yyyyMMddTHHmmssZ");
            string dateStamp = t.ToString("yyyyMMdd");
            string canonicalUri = "/";
            string canonicalQueryString = query;
            string canonicalHeaders = $"host:{host}\n" + $"x-amz-date:{amzDate}\n";
            string signedHeaders = "host;x-amz-date";
            string payloadHash = Hash("");
            string canonicalRequest =
                "GET\n" +
                canonicalUri + "\n" +
                canonicalQueryString + "\n" +
                canonicalHeaders + "\n" +
                signedHeaders + "\n" +
                payloadHash;
            string algorithm = "AWS4-HMAC-SHA256";
            string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
            string stringToSign =
                algorithm + "\n" +
                amzDate + "\n" +
                credentialScope + "\n" +
                Hash(canonicalRequest);
            byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
            string signature = ToHexString(HmacSHA256(stringToSign, signingKey));
            string authorizationHeader =
                $"{algorithm} Credential={accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";
            request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        private static string Hash(string data)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return ToHexString(bytes);
        }

        private static byte[] HmacSHA256(string data, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kDate = HmacSHA256(dateStamp, Encoding.UTF8.GetBytes("AWS4" + key));
            byte[] kRegion = HmacSHA256(regionName, kDate);
            byte[] kService = HmacSHA256(serviceName, kRegion);
            byte[] kSigning = HmacSHA256("aws4_request", kService);
            return kSigning;
        }

        private static string ToHexString(byte[] bytes) =>
            string.Concat(bytes.Select(b => b.ToString("x2")));

    }

}

const YAML = require("yaml");
const axios = require("axios");

module.exports = async (req, res) => {
  const url = req.query.url;
  const target = req.query.target;
  const regions = req.query.region ? req.query.region.split(",") : [];
  const excludeFilter = req.query["exclude-filter"]
    ? req.query["exclude-filter"].split("|")
    : [];
  console.log("excludeFilter", excludeFilter);
  console.log(`query: ${JSON.stringify(req.query)}`);
  if (url === undefined) {
    res.status(400).send("Missing parameter: url");
    return;
  }

  console.log(`Fetching urls: ${url}`);
  let allProxies = [];
  try {
    const urls = url.split("|");
    console.log("[urls]", urls);
    const fetchPromises = urls.map(async (singleUrl) => {
      try {
        const result = await axios({
          url: singleUrl,
          headers: {
            "User-Agent":
              "clash-verge/v2.3.2 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
          },
        });

        // console.log("result", result.data);

        const config = YAML.parse(result.data);
        return config.proxies || [];
      } catch (error) {
        console.error(`Error fetching/parsing ${singleUrl}`, error.message);
        return [];
      }
    });

    const results = await Promise.allSettled(fetchPromises);
    allProxies = results
      .filter((result) => result.status === "fulfilled")
      .flatMap((result) => result.value);

    if (allProxies.length === 0) {
      res.status(400).send("No valid proxies found in any of the configs");
      return;
    }
  } catch (error) {
    res.status(500).send(`Unexpected error: ${error.message}`);
    return;
  }

  // Apply exclude-filter
  if (excludeFilter.length > 0) {
    const regex = new RegExp(excludeFilter.join("|"), "i");
    allProxies = allProxies.filter((proxy) => {
      const shouldKeep = !regex.test(proxy.name);
      return shouldKeep;
    });
  }

  if (target === "surge") {
    const supportedProxies = allProxies.filter((proxy) =>
      ["ss", "vmess", "trojan"].includes(proxy.type)
    );
    const surgeProxies = supportedProxies.map((proxy) => {
      console.log(proxy.server);
      const common = `${proxy.name} = ${proxy.type}, ${proxy.server}, ${proxy.port}`;
      if (proxy.type === "ss") {
        // ProxySS = ss, example.com, 2021, encrypt-method=xchacha20-ietf-poly1305, password=12345, obfs=http, obfs-host=example.com, udp-relay=true
        if (proxy.plugin === "v2ray-plugin") {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge does not support Shadowsocks with v2ray-plugin`
          );
          return;
        }
        let result = `${common}, encrypt-method=${proxy.cipher}, password=${proxy.password}`;
        if (proxy.plugin === "obfs") {
          const mode = proxy?.["plugin-opts"].mode;
          const host = proxy?.["plugin-opts"].host;
          result = `${result}, obfs=${mode}${
            host ? `, obfs-host=example.com ${host}` : ""
          }`;
        }
        if (proxy.udp) {
          result = `${result}, udp-relay=${proxy.udp}`;
        }
        return result;
      } else if (proxy.type === "vmess") {
        // ProxyVmess = vmess, example.com, 2021, username=0233d11c-15a4-47d3-ade3-48ffca0ce119, skip-cert-verify=true, sni=example.com, tls=true, ws=true, ws-path=/path
        if (["h2", "http", "grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Vmess(${proxy.network})`
          );
          return;
        }
        let result = `${common}, username=${proxy.uuid}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.servername) {
          result = `${result}, sni=${proxy.servername}`;
        }
        if (proxy.tls) {
          result = `${result}, tls=${proxy.tls}`;
        }
        if (proxy.network === "ws") {
          result = `${result}, ws=true`;
        }
        if (proxy["ws-path"]) {
          result = `${result}, ws-path=${proxy["ws-path"]}`;
        }
        return result;
      } else if (proxy.type === "trojan") {
        // ProxyTrojan = trojan, example.com, 2021, username=user, password=12345, skip-cert-verify=true, sni=example.com
        if (["grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Trojan(${proxy.network})`
          );
          return;
        }
        let result = `${common}, password=${proxy.password}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.sni) {
          result = `${result}, sni=${proxy.sni}`;
        }
        return result;
      }
    });
    const proxies = surgeProxies.filter((p) => p !== undefined);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.status(200).send(proxies.join("\n"));
  } else if (target === "quantumult-x" || target === "quanx") {
    const supportedProxies = allProxies.filter((proxy) =>
      ["ss", "vmess", "trojan"].includes(proxy.type)
    );

    const quanXProxies = supportedProxies.map((proxy) => {
      const common = `server_check_url=http://www.gstatic.com/generate_204`;
      if (proxy.type === "ss") {
        // shadowsocks=example.com:443, method=chacha20-ietf-poly1305, password=pwd, obfs=http, obfs-host=example.com, tag=ss-01
        if (proxy.plugin === "v2ray-plugin") {
          console.log(
            `Skip convert proxy ${proxy.name} because QuantumultX does not support Shadowsocks with v2ray-plugin`
          );
          return;
        }
        const result = `shadowsocks=${proxy.server}:${proxy.port}, method=${proxy.cipher}, password=${proxy.password}, obfs=http, obfs-host=bing.com, obfs-uri=/resource/file, tag=${proxy.name}, ${common}`;

        return result;
      } else if (proxy.type === "vmess") {
        // vmess=example.com:443, method=chacha20-poly1305, password=uuid, obfs=ws, obfs-uri=/path, tag=vmess-01
        if (["h2", "http", "grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because QuantumultX may not support Vmess(${proxy.network})`
          );
          return;
        }
        let result = `vmess=${proxy.server}:${proxy.port}, method=auto, password=${proxy.uuid}`;
        if (proxy.network === "ws") {
          result = `${result}, obfs=ws`;
          if (proxy["ws-path"]) {
            result = `${result}, obfs-uri=${proxy["ws-path"]}`;
          }
        }
        if (proxy.tls) {
          result = `${result}, over-tls=true`;
          if (proxy.servername) {
            result = `${result}, tls-host=${proxy.servername}`;
          }
          if (proxy["skip-cert-verify"]) {
            result = `${result}, tls-verification=${!proxy[
              "skip-cert-verify"
            ]}`;
          }
        }
        result = `${result}, tag=${proxy.name}, ${common}`;
        return result;
      } else if (proxy.type === "trojan") {
        // trojan=example.com:443, password=pwd, over-tls=true, tls-verification=true, tls-host=example.com, tag=trojan-01
        if (["grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because QuantumultX may not support Trojan(${proxy.network})`
          );
          return;
        }
        let result = `trojan=${proxy.server}:${proxy.port}, password=${proxy.password}, over-tls=true`;
        if (proxy.sni) {
          result = `${result}, tls-host=${proxy.sni}`;
        }
        if (proxy["skip-cert-verify"]) {
          result = `${result}, tls-verification=${!proxy["skip-cert-verify"]}`;
        }
        result = `${result}, tag=${proxy.name}, ${common}`;
        return result;
      }
    });
    const proxies = quanXProxies.filter(Boolean);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.status(200).send(proxies.join("\n"));
  } else {
    const proxies = allProxies.filter((proxy) => {
      if (regions.length) {
        return regions.some((region) => proxy.server.includes(region));
      }
      return true;
    });
    const response = YAML.stringify({ proxies });
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.status(200).send(response);
  }
};

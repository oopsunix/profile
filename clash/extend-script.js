/**
 * @author   oopsunix
 * @version  1.0.0
 * @date     2025-03-03
 */


// Define main function (script entry)

// function main(config, profileName) {
//   return config;
// }

// Define the `main` function

const proxyName = "代理模式";

function main(params) {
    if (!params.proxies) return params;
    // 覆盖原配置中的规则
    overwriteRules(params);
    // 覆盖原配置中的代理组
    overwriteProxyGroups(params);
    // 覆盖原配置中DNS配置
    overwriteDns(params);

    // 返回修改后的配置
    return params;
}

//覆写规则
function overwriteRules(params) {
    const customRules = [
      // 在此添加自定义规则, 最高优先级。
      // 为了方便区分，可设置 全局代理模式 或 自定义代理组。
      // 示例1 ：使用 全局代理模式
      //"DOMAIN-SUFFIX,linux.do," + proxyName,
      // 示例2 ：使用 自定义代理组1
      //"DOMAIN-SUFFIX,gstatic.com,自定义代理组1",
      // 示例3 ：使用 自定义代理组2
      //"DOMAIN-SUFFIX,googleapis.com,自定义代理组2",

      // 自定义规则
    ];


    const rules = [
        ...customRules,
        "RULE-SET,reject,广告拦截",
        "RULE-SET,direct,DIRECT",
        "RULE-SET,cncidr,DIRECT",
        "RULE-SET,private,DIRECT",
        "RULE-SET,lancidr,DIRECT",
        "RULE-SET,applications,DIRECT",
        "RULE-SET,telegramcidr,电报消息,no-resolve",
        "RULE-SET,microsoft,微软服务,no-resolve",
        "RULE-SET,google,谷歌服务,no-resolve",
        "RULE-SET,icloud,苹果服务,no-resolve",
        "RULE-SET,apple,苹果服务,no-resolve",
        "RULE-SET,gfw," + proxyName,
        "RULE-SET,proxy," + proxyName,
        "RULE-SET,tld-not-cn," + proxyName,
        "GEOIP,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT,no-resolve",
        "MATCH,漏网之鱼",
    ];
    const ruleProviders = {
        icloud: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
            path: "./ruleset/icloud.yaml",
            interval: 86400,
        },
        apple: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
            path: "./ruleset/apple.yaml",
            interval: 86400,
        },
        google: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
            path: "./ruleset/google.yaml",
            interval: 86400,
        },
        microsoft: {
            type: "http",
            behavior: "domain",
            url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list",
            path: "./ruleset/microsoft.txt",
            interval: 86400,
        },
        telegramcidr: {
            type: "http",
            behavior: "ipcidr",
            url: "hhttps://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
            path: "./ruleset/custom/telegramcidr.yaml"
        },
        // 广告域名列表
        reject: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
            path: "./ruleset/reject.yaml",
            interval: 86400,
        },
        // 代理域名列表
        proxy: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
            path: "./ruleset/proxy.yaml",
            interval: 86400,
        },
        // 直连域名列表
        direct: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
            path: "./ruleset/direct.yaml",
            interval: 86400,
        },
        // 私有网络专用域名列表
        private: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
            path: "./ruleset/private.yaml",
            interval: 86400,
        },
        // GFWList 域名列表
        gfw: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
            path: "./ruleset/gfw.yaml",
            interval: 86400,
        },
        // 非中国大陆使用的顶级域名列表
        "tld-not-cn": {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
            path: "./ruleset/tld-not-cn.yaml",
            interval: 86400,
        },
        // 中国大陆 IP 地址列表
        cncidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
            path: "./ruleset/cncidr.yaml",
            interval: 86400,
        },
        // 局域网 IP 及保留 IP 地址列表
        lancidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
            path: "./ruleset/lancidr.yaml",
            interval: 86400,
        },
        // 需要直连的常见软件列表
        applications: {
            type: "http",
            behavior: "classical",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
            path: "./ruleset/applications.yaml",
            interval: 86400,
        },
    };
    params["rule-providers"] = ruleProviders;
    params["rules"] = rules;
}

//覆写代理组
function overwriteProxyGroups(params) {
    // 添加自用代理
    params.proxies.push(
        //  { name: '1-香港-示例', type: *, server: **, port: *, cipher: **, password: **, udp: true }

    );

    // 所有代理
    const allProxies = params["proxies"].map((e) => e.name);
    // 自动选择代理组，按地区分组选延迟最低
    const autoProxyGroupRegexs = [
        { name: "HK-自动选择", regex: /香港|HK|Hong|🇭🇰/ },
        { name: "TW-自动选择", regex: /台湾|TW|Taiwan|Wan|🇨🇳|🇹🇼/ },
        { name: "SG-自动选择", regex: /新加坡|狮城|SG|Singapore|🇸🇬/ },
        { name: "JP-自动选择", regex: /日本|JP|Japan|🇯🇵/ },
        { name: "US-自动选择", regex: /美国|US|United States|America|🇺🇸/ },
        { name: "其它-自动选择", regex: /(?!.*(?:剩余|到期|主页|官网|游戏|关注))(.*)/ },
    ];

    const autoProxyGroups = autoProxyGroupRegexs
        .map((item) => ({
            name: item.name,
            type: "url-test",
            url: "http://www.gstatic.com/generate_204",
            interval: 300,
            tolerance: 50,
            proxies: getProxiesByRegex(params, item.regex),
            hidden: true,
        }))
        .filter((item) => item.proxies.length > 0);

    //手工选择代理组
    const manualProxyGroups = [
        { name: "HK-手工选择", regex: /香港|HK|Hong|🇭🇰/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg" },
        { name: "TW-手工选择", regex: /台湾|TW|Taiwan|Wan|🇨🇳|🇹🇼/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg" },
        { name: "SG-手工选择", regex: /新加坡|狮城|SG|Singapore|🇸🇬/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg" },
        { name: "JP-手工选择", regex: /日本|JP|Japan|🇯🇵/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg" },
        { name: "US-手工选择", regex: /美国|US|United States|America|🇺🇸/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg" },
    ];

    const manualProxyGroupsConfig = manualProxyGroups
        .map((item) => ({
            name: item.name,
            type: "select",
            proxies: getManualProxiesByRegex(params, item.regex),
            icon: item.icon,
            hidden: false,
        }))
        .filter((item) => item.proxies.length > 0);

    const groups = [
        {
            name: proxyName,
            type: "select",
            url: "http://www.gstatic.com/generate_204",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg",
            proxies: [
                "自动选择",
                "手动选择",
                "负载均衡(散列)",
                "负载均衡(轮询)",
                "DIRECT",
            ],
        },
        {
            name: "手动选择",
            type: "select",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg",
            proxies: allProxies,
        },
        {
            name: "ALL-自动选择",
            type: "url-test",
            url: "http://www.gstatic.com/generate_204",
            interval: 300,
            tolerance: 50,
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "自动选择",
            type: "select",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg",
            proxies: ["ALL-自动选择"],
        },
        {
            name: "负载均衡(散列)",
            type: "load-balance",
            url: "http://www.gstatic.com/generate_204",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
            interval: 300,
            "max-failed-times": 3,
            strategy: "consistent-hashing",
            lazy: true,
            proxies: allProxies,
        },
        {
            name: "负载均衡(轮询)",
            type: "load-balance",
            url: "http://www.gstatic.com/generate_204",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
            interval: 300,
            "max-failed-times": 3,
            strategy: "round-robin",
            lazy: true,
            proxies: allProxies,
        },
        {
            name: "微软服务",
            type: "select",
            proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/microsoft.svg"
        },
        {
            name: "苹果服务",
            type: "select",
            proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/apple.svg"
        },
        {
            name: "谷歌服务",
            type: "select",
            proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/google.svg"
        },
        {
            name: "电报消息",
            type: "select",
            proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg"
        },
        // {
        //     name: "ChatGPT",
        //     type: "select",
        //     proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
        //     // "include-all": true,
        //     icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg"
        // },
        // {
        //     name: "Claude",
        //     type: "select",
        //     proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
        //     // "include-all": true,
        //     icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/claude.svg"
        // },
        // {
        //     name: "Spotify",
        //     type: "select",
        //     proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择"],
        //     // "include-all": true,
        //     icon: "https://storage.googleapis.com/spotifynewsroom-jp.appspot.com/1/2020/12/Spotify_Icon_CMYK_Green.png"
        // },
        {
            name: "漏网之鱼",
            type: "select",
            proxies: ["DIRECT", proxyName],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg"
        },
        {
            name: "广告拦截",
            type: "select",
            proxies: ["REJECT", "DIRECT", proxyName],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/block.svg"
        },
    ];

    autoProxyGroups.length &&
        groups[2].proxies.unshift(...autoProxyGroups.map((item) => item.name));
    groups.push(...autoProxyGroups);
    groups.push(...manualProxyGroupsConfig);
    params["proxy-groups"] = groups;

}

//防止dns泄露
function overwriteDns(params) {
    const cnDnsList = [
        "https://223.5.5.5/dns-query",  // 阿里云公共DNS
        "https://1.12.12.12/dns-query", // 腾讯DNSPod
        "https://doh.360.cn/dns-query"  // 360安全DNS
    ];
    const trustDnsList = [
        'quic://dns.cooluc.com',
        'https://94.140.14.140/dns-query',  // AdGuard DNS
        "https://1.0.0.1/dns-query",        // Cloudflare(主)
        "https://1.1.1.1/dns-query",        // Cloudflare(备)
    ];

    const dnsOptions = {
        enable: true,
        ipv6: true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
          // 本地主机/设备
          "+.lan",
          "+.local",
          "+.localhost",
          "+.time.*",
          "+.ntp.*",
          // Windows网络出现小地球图标
          "+.msftconnecttest.com",
          "+.msftncsi.com",
          // QQ快速登录检测失败
          "localhost.ptlogin2.qq.com",
          "localhost.sec.qq.com",
          // 微信快速登录检测失败
          "localhost.work.weixin.qq.com"
        ],
        "default-nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"], // 用于解析其他DNS服务器、和节点的域名, 必须为IP, 可为加密DNS。注意这个只用来解析节点和其他的dns，其他网络请求不归他管
        nameserver: cnDnsList, // 其他网络请求都归他管

        // 这个用于覆盖上面的 nameserver
        "nameserver-policy": {
            "geosite:cn": cnDnsList,
            "geosite:geolocation-!cn": trustDnsList,
            // 如果你有一些内网使用的DNS，应该定义在这里，多个域名用英文逗号分割
            // '+.公司域名.com, www.4399.com, +.baidu.com': '10.0.0.1'
        },
    };

    // GitHub加速前缀
    const githubPrefix = "https://gh.llkk.cc/";

    // GEO数据GitHub资源原始下载地址
    const rawGeoxURLs = {
        geoip:
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
        geosite:
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
    };

    // 生成带有加速前缀的GEO数据资源对象
    const accelURLs = Object.fromEntries(
        Object.entries(rawGeoxURLs).map(([key, githubUrl]) => [
            key,
            `${githubPrefix}${githubUrl}`,
        ])
    );

    const otherOptions = {
        "unified-delay": true,
        "tcp-concurrent": true,
        profile: {
            "store-selected": true,
            "store-fake-ip": true,
        },
        sniffer: {
            enable: true,
            sniff: {
                TLS: {
                    ports: [443, 8443],
                },
                HTTP: {
                    ports: [80, "8080-8880"],
                    "override-destination": true,
                },
            },
        },
        "geodata-mode": true,
        "geox-url": accelURLs,
    };

    params.dns = { ...params.dns, ...dnsOptions };
    Object.keys(otherOptions).forEach((key) => {
        params[key] = otherOptions[key];
    });
}

function getProxiesByRegex(params, regex) {
    const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
    return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
}

function getManualProxiesByRegex(params, regex) {
    const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
    return matchedProxies.length > 0 ? matchedProxies : ["DIRECT", "手动选择", proxyName];
}

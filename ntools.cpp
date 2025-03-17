// git clone https://github.com/ipkn/crow.git
// g++ -std=c++17 -O2 -I crow/include -o ntools ntools.cpp -lpthread

#include "crow.h"  // Compile with -I crow/include
#include <iostream>
#include <cstdio>
#include <array>
#include <regex>
#include <chrono>
#include <vector>
#include <sstream>
#include <algorithm>
#include <future>
#include <cctype>

// Standard UNIX headers for exec functions and DNS resolution
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

//---------------------------------------------
// Validation functions
//---------------------------------------------
bool isValidIP(const std::string &ip) {
    const std::regex ip_regex(
      "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}"
      "(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    return std::regex_match(ip, ip_regex);
}

bool isValidDomain(const std::string &domain) {
    if(domain.find(' ') != std::string::npos)
        return false;
    if(domain.length() < 3)
        return false;
    return domain.find('.') != std::string::npos;
}

bool isPrivateIP(const std::string &ip) {
    unsigned int a, b, c, d;
    char dot;
    std::istringstream iss(ip);
    if(!(iss >> a >> dot >> b >> dot >> c >> dot >> d))
        return false; // Shouldn't happen if validated
    if(a == 10)
        return true;
    if(a == 172 && (b >= 16 && b <= 31))
        return true;
    if(a == 192 && b == 168)
        return true;
    return false;
}

bool isAllowedIP(const std::string &ip) {
    if(!isValidIP(ip))
        return false;
    if(ip.compare(0,4,"127.") == 0)
        return false;
    return true;
}

bool isAllowedTarget(const std::string &target) {
    if(!(isValidIP(target) || isValidDomain(target)))
        return false;
    if(target == "localhost" || target.compare(0,4,"127.")==0)
        return false;
    return true;
}

std::string resolveDomainToIP(const std::string &domain) {
    hostent *host = gethostbyname(domain.c_str());
    if(host == nullptr || host->h_addr_list[0] == nullptr)
        return "";
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr_list[0], ipstr, INET_ADDRSTRLEN);
    return std::string(ipstr);
}

//---------------------------------------------
// Helper: trim whitespace from string
//---------------------------------------------
std::string trim(const std::string &str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if(first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

//---------------------------------------------
// Helper: sanitize domain for WHOIS queries.
// Strips common subdomains like "www."
//---------------------------------------------
std::string sanitizeDomain(const std::string &domain) {
    if(domain.find("www.") == 0) {
        return domain.substr(4);
    }
    return domain;
}

//---------------------------------------------
// Secured exec() function using a command whitelist.
// Only commands starting with ping, traceroute, whois, nslookup, or nmap are allowed.
//---------------------------------------------
std::string exec(const char *cmd) {
    std::string command = trim(cmd);
    // Allowed command prefixes.
    const std::vector<std::string> allowedCommands = {
        "ping",
        "traceroute",
        "whois",
        "nslookup",
        "nmap"  // Used for portscan endpoint.
    };

    // Check if the command starts with one of the allowed commands.
    bool isAllowed = false;
    for (const auto &allowed : allowedCommands) {
        if (command.find(allowed) == 0) {
            isAllowed = true;
            break;
        }
    }

    if (!isAllowed) {
        return "Command not allowed!";
    }

    std::array<char,128> buffer;
    std::string result;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe)
        return "popen failed!";
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        result += buffer.data();
    pclose(pipe);
    return result;
}

//---------------------------------------------
// Global CORS middleware for Crow
//---------------------------------------------
struct CORS {
    struct context { };
    void before_handle(crow::request &req, crow::response &res, context &) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
    }
    void after_handle(crow::request &, crow::response &, context &) { }
};

//---------------------------------------------
// Main
//---------------------------------------------
int main() {
    crow::App<CORS> app;

    // ---------------------------------------------
    // /ping endpoint
    // ---------------------------------------------
    CROW_ROUTE(app, "/ping").methods("GET"_method)([](const crow::request &req) {
        auto targetParam = req.url_params.get("target");
        if(!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);
        if(!isAllowedTarget(targetStr))
            return crow::response(400, "Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");
        // Execute the ping command with 4 ICMP packets.
        std::string command = "ping -c 4 " + targetStr;
        std::string output = exec(command.c_str());
        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // ---------------------------------------------
    // /portscan endpoint using nmap.
    // Blocks scanning of burgess.services by domain or IP.
    // ---------------------------------------------
    CROW_ROUTE(app, "/portscan").methods("GET"_method)([&](const crow::request &req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);

        // Block scanning if target equals "burgess.services" or "www.burgess.services"
        if (targetStr == "burgess.services" || targetStr == "www.burgess.services") {
            return crow::response(400, "Scanning this domain is not allowed");
        }
        
        // Resolve the IP for burgess.services and block if the target IP matches.
        std::string blockedIP = resolveDomainToIP("burgess.services");
        if (isValidIP(targetStr) && targetStr == blockedIP) {
            return crow::response(400, "Scanning this domain is not allowed");
        }
        
        // If target is a domain, resolve it.
        if (!isValidIP(targetStr) && isValidDomain(targetStr)) {
            std::string resolvedIP = resolveDomainToIP(targetStr);
            if (resolvedIP.empty())
                return crow::response(400, "Unable to resolve domain name to IPv4 address");
            targetStr = resolvedIP;
        }
        if (!isAllowedIP(targetStr) || isPrivateIP(targetStr))
            return crow::response(400, "Scanning private IP ranges is not allowed");

        crow::json::wvalue result;
        auto portParam = req.url_params.get("port");
        auto portStartParam = req.url_params.get("port_start");
        auto portEndParam = req.url_params.get("port_end");
        int startPort = 0, endPort = 0;
        
        if (portStartParam && portEndParam) {
            try {
                startPort = std::stoi(portStartParam);
                endPort = std::stoi(portEndParam);
            } catch (...) {
                return crow::response(400, "Invalid port range values");
            }
            if (startPort < 1 || endPort > 65535 || startPort > endPort)
                return crow::response(400, "Port range out of bounds or invalid");
            
            // Build nmap command for range scan.
            std::string nmapCommand = "nmap -p " + std::to_string(startPort) + "-" + std::to_string(endPort)
                                        + " " + targetStr + " -oX -";
            std::string nmapOutput = exec(nmapCommand.c_str());
            
            // Parse XML output for TCP port states.
            std::regex portRegex("<port protocol=\"tcp\" portid=\"(\\d+)\">.*?<state state=\"([^\"]+)\"");
            std::smatch match;
            std::string::const_iterator searchStart(nmapOutput.cbegin());
            std::vector<std::pair<int, std::string>> ports;
            while (std::regex_search(searchStart, nmapOutput.cend(), match, portRegex)) {
                int port = std::stoi(match[1].str());
                std::string state = match[2].str();
                ports.push_back(std::make_pair(port, state));
                searchStart = match.suffix().first;
            }
            std::sort(ports.begin(), ports.end(),
                [](const std::pair<int, std::string> &a, const std::pair<int, std::string> &b) {
                    return a.first < b.first;
                }
            );
            std::vector<bool> portResults;
            for (int p = startPort; p <= endPort; ++p) {
                bool open = false;
                for (size_t i = 0; i < ports.size(); ++i) {
                    if (ports[i].first == p) {
                        open = (ports[i].second == "open");
                        break;
                    }
                }
                portResults.push_back(open);
            }
            // If scanning a single port via range, handle it as a single port.
            if (startPort == endPort) {
                result["target"] = targetStr;
                result["port"] = std::to_string(startPort);
                result["open"] = portResults.empty() ? false : portResults[0];
                return crow::response(result);
            }
            // Group consecutive ports.
            std::vector<crow::json::wvalue> openGroups;
            std::vector<crow::json::wvalue> closedGroups;
            int currentStart = startPort;
            bool currentState = portResults[0];
            for (int p = startPort + 1; p <= endPort; ++p) {
                bool state = portResults[p - startPort];
                if (state != currentState) {
                    crow::json::wvalue group;
                    group["start"] = currentStart;
                    group["end"] = p - 1;
                    if (currentState)
                        openGroups.push_back(std::move(group));
                    else
                        closedGroups.push_back(std::move(group));
                    currentState = state;
                    currentStart = p;
                }
            }
            {
                crow::json::wvalue group;
                group["start"] = currentStart;
                group["end"] = endPort;
                if (currentState)
                    openGroups.push_back(std::move(group));
                else
                    closedGroups.push_back(std::move(group));
            }
            // Build JSON objects with numeric keys.
            crow::json::wvalue openRangesObj;
            for (size_t i = 0; i < openGroups.size(); i++) {
                openRangesObj[std::to_string(i)] = std::move(openGroups[i]);
            }
            crow::json::wvalue closedRangesObj;
            for (size_t i = 0; i < closedGroups.size(); i++) {
                closedRangesObj[std::to_string(i)] = std::move(closedGroups[i]);
            }
            bool overall = false;
            for (bool b : portResults) {
                if (b) { overall = true; break; }
            }
            result["target"] = targetStr;
            result["scan_range"]["start"] = startPort;
            result["scan_range"]["end"] = endPort;
            result["port"] = std::to_string(startPort) + "-" + std::to_string(endPort);
            result["overall"] = overall;
            result["status"] = overall ? "Open" : "Closed";
            result["open_ranges"] = std::move(openRangesObj);
            result["closed_ranges"] = std::move(closedRangesObj);
        } else if (portParam) {
            int port = 0;
            try {
                port = std::stoi(portParam);
            } catch (...) {
                return crow::response(400, "Invalid port value");
            }
            if (port < 1 || port > 65535)
                return crow::response(400, "Port number out of range (1-65535)");
            std::string nmapCommand = "nmap -p " + std::to_string(port) + " " + targetStr + " -oX -";
            std::string nmapOutput = exec(nmapCommand.c_str());
            std::regex portRegex("<port protocol=\"tcp\" portid=\"(\\d+)\">.*?<state state=\"([^\"]+)\"");
            std::smatch match;
            bool open = false;
            if (std::regex_search(nmapOutput, match, portRegex)) {
                open = (match[2].str() == "open");
            }
            crow::json::wvalue result;
            result["target"] = targetStr;
            result["port"] = std::to_string(port);
            result["open"] = open;
            return crow::response(result);
        } else {
            return crow::response(400, "Missing port parameter. Specify either 'port' or both 'port_start' and 'port_end'");
        }
        return crow::response(result);
    });

    // ---------------------------------------------
    // /traceroute endpoint with restricted hops.
    // Replaces the first two hop lines (after the header) with a custom message.
    // ---------------------------------------------
    CROW_ROUTE(app, "/traceroute").methods("GET"_method)([](const crow::request &req) {
        // Retrieve the target parameter from the query string.
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string target(targetParam);
        if (!isAllowedTarget(target))
            return crow::response(400, "Invalid target");

        // Execute the traceroute command.
        std::string command = "traceroute " + target;
        std::string output = exec(command.c_str());

        // Split the output into individual lines.
        std::istringstream iss(output);
        std::string line;
        std::vector<std::string> lines;
        while (std::getline(iss, line)) {
            lines.push_back(line);
        }
        
        // Assuming the first line is the header, replace the first two hop lines (if available).
        if (lines.size() > 1) {
            lines[1] = "1 *** RESTRICTED ***";  // Replace first hop.
            if (lines.size() > 2)
                lines[2] = "2 *** RESTRICTED ***";  // Replace second hop.
        }
        
        // Reassemble the modified lines.
        std::string modified_output;
        for (const auto &l : lines) {
            modified_output += l + "\n";
        }
        
        crow::json::wvalue result;
        result["result"] = modified_output;
        return crow::response(result);
    });

    // ---------------------------------------------
    // /whois endpoint with input sanitization.
    // Strips common subdomains (like "www.") before querying.
    // ---------------------------------------------
    CROW_ROUTE(app, "/whois").methods("GET"_method)([](const crow::request &req) {
        // Retrieve the target parameter.
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string target(targetParam);
        if (!isAllowedTarget(target))
            return crow::response(400, "Invalid target");

        // Sanitize the domain by stripping "www." if present.
        target = sanitizeDomain(target);

        // Execute the whois command to fetch registration details.
        std::string command = "whois " + target;
        std::string output = exec(command.c_str());

        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // ---------------------------------------------
    // /nslookup endpoint with header removal.
    // Removes the "Server:" and "Address:" header block from the output.
    // ---------------------------------------------
    CROW_ROUTE(app, "/nslookup").methods("GET"_method)([](const crow::request &req) {
        // Retrieve the target parameter.
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string target(targetParam);
        if (!isAllowedTarget(target))
            return crow::response(400, "Invalid target");

        // Execute the nslookup command.
        std::string command = "nslookup " + target;
        std::string output = exec(command.c_str());

        // Process the output to remove the header block.
        // This skips all lines until an empty line is encountered.
        std::istringstream iss(output);
        std::string line;
        std::string filteredOutput;
        bool headerEnded = false;
        while (std::getline(iss, line)) {
            if (!headerEnded) {
                if (line.empty()) {
                    headerEnded = true;
                }
                continue;
            }
            filteredOutput += line + "\n";
        }

        crow::json::wvalue result;
        result["result"] = filteredOutput;
        return crow::response(result);
    });

    // ---------------------------------------------
    // Catch-all OPTIONS route.
    // ---------------------------------------------
    CROW_ROUTE(app, "/<path>")
        .methods("OPTIONS"_method)([](const crow::request &req, const std::string &/*path*/) {
            crow::response res;
            res.code = 200;
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        });

    // Run the server on port 18080 with multithreading enabled. - allows outside connections access to the api
    //app.port(18080).multithreaded().run();
    
    // Only accessible to the localhost
    app.bindaddr("127.0.0.1").port(18080).multithreaded().run();
    return 0;
}

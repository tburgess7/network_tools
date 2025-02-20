#include "crow.h"  // Compile with -I crow/include
#include <iostream>
#include <cstdio>
#include <array>
#include <cstring>
#include <regex>
#include <chrono>
#include <vector>
#include <sstream>

// Standard UNIX headers for exec functions and DNS resolution
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

// Boost.Asio headers
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

using boost::asio::ip::tcp;

//---------------------------------------------
// Validation functions
//---------------------------------------------
// Validate that the provided string is a valid IPv4 address.
bool isValidIP(const std::string& ip) {
    const std::regex ip_regex(
        "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}"
        "(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"
    );
    return std::regex_match(ip, ip_regex);
}

// Relaxed domain validation: must contain at least one dot,
// no spaces, and at least 3 characters.
bool isValidDomain(const std::string& domain) {
    if (domain.find(' ') != std::string::npos) return false;
    if (domain.length() < 3) return false;
    return domain.find('.') != std::string::npos;
}

// Check if an IPv4 address is in a private range.
bool isPrivateIP(const std::string& ip) {
    unsigned int a, b, c, d;
    char dot;
    std::istringstream iss(ip);
    if (!(iss >> a >> dot >> b >> dot >> c >> dot >> d))
        return false;  // Shouldn't happen if ip is validated
    if (a == 10) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    return false;
}

// For endpoints like portscan we require only a valid non-localhost IPv4 address.
bool isAllowedIP(const std::string& ip) {
    if (!isValidIP(ip))
        return false;
    if (ip.compare(0, 4, "127.") == 0)
        return false;
    return true;
}

// Common check for endpoints that accept both IPv4 and domain names.
bool isAllowedTarget(const std::string& target) {
    if (!(isValidIP(target) || isValidDomain(target)))
        return false;
    if (target == "localhost" || target.compare(0, 4, "127.") == 0)
        return false;
    return true;
}

// Resolve a domain name to an IPv4 address. Returns empty string on failure.
std::string resolveDomainToIP(const std::string& domain) {
    hostent* host = gethostbyname(domain.c_str());
    if (host == nullptr || host->h_addr_list[0] == nullptr)
        return "";
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr_list[0], ipstr, INET_ADDRSTRLEN);
    return std::string(ipstr);
}

//---------------------------------------------
// Helper: exec() for shell commands
//---------------------------------------------
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        return "popen failed!";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}

//---------------------------------------------
// Boost.Asio based port scanning with debug output
//---------------------------------------------
bool check_port(const std::string &host, int port, int timeout_ms)
{
    try {
        boost::asio::io_context io;
        tcp::resolver resolver(io);
        boost::system::error_code ec;
        auto endpoints = resolver.resolve(host, std::to_string(port), ec);
        if(ec) {
            std::cerr << "Error resolving host " << host << ": " << ec.message() << "\n";
            return false;
        }
        
        tcp::socket socket(io);
        bool connect_success = false;
        bool timeout_occurred = false;
        
        boost::asio::steady_timer timer(io);
        timer.expires_after(std::chrono::milliseconds(timeout_ms));
        timer.async_wait([&](const boost::system::error_code &error) {
            if (!error) {
                timeout_occurred = true;
                socket.close();
                std::cerr << "Timer expired (timeout " << timeout_ms << " ms) for port " << port << "\n";
            }
        });
        
        boost::asio::async_connect(socket, endpoints,
            [&](const boost::system::error_code &error, const tcp::endpoint &) {
                if (!error)
                    connect_success = true;
                else
                    std::cerr << "Async connect error on port " << port << ": " << error.message() << "\n";
                timer.cancel();
            });
        
        io.run();
        return connect_success && !timeout_occurred;
    }
    catch (std::exception &e) {
        std::cerr << "Exception in check_port for port " << port << ": " << e.what() << "\n";
        return false;
    }
}

//---------------------------------------------
// Global CORS middleware for Crow
//---------------------------------------------
struct CORS {
    struct context { };
    void before_handle(crow::request& req, crow::response& res, context&) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
    }
    void after_handle(crow::request&, crow::response&, context&) { }
};

// Helper function for endpoints that must block private IP ranges.
// If the target is a domain, it is resolved; if the resulting IP is private, returns an empty string.
std::string validateAndResolveTarget(const std::string &target) {
    // Check basic validity.
    if (!isAllowedTarget(target))
        return "";
    // If it's a valid IP, use it.
    if (isValidIP(target))
        return target;
    // Otherwise, resolve the domain.
    std::string resolved = resolveDomainToIP(target);
    if (resolved.empty())
        return "";
    if (!isAllowedIP(resolved)) // If resolved IP is private or localhost, block.
        return "";
    return resolved;
}

int main() {
    crow::App<CORS> app;
    const int timeout_ms = 2000; // Timeout for port scan in milliseconds

    // /ping endpoint: Accepts a valid IPv4 address or domain name, but blocks if target resolves to a private IP.
    CROW_ROUTE(app, "/ping").methods("GET"_method)([](const crow::request& req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);
        if (!isAllowedTarget(targetStr))
            return crow::response(400, "Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");
        
        std::string ip = (isValidIP(targetStr)) ? targetStr : resolveDomainToIP(targetStr);
        if (ip.empty() || isPrivateIP(ip))
            return crow::response(400, "Access to private IP ranges is not allowed");
        
        std::string command = "ping -c 4 " + targetStr;
        std::string output = exec(command.c_str());
        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // /traceroute endpoint.
    CROW_ROUTE(app, "/traceroute").methods("GET"_method)([](const crow::request& req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);
        if (!isAllowedTarget(targetStr))
            return crow::response(400, "Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");

        std::string ip = (isValidIP(targetStr)) ? targetStr : resolveDomainToIP(targetStr);
        if (ip.empty() || isPrivateIP(ip))
            return crow::response(400, "Access to private IP ranges is not allowed");

        std::string command = "traceroute " + targetStr;
        std::string output = exec(command.c_str());
        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // /whois endpoint.
    CROW_ROUTE(app, "/whois").methods("GET"_method)([](const crow::request& req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);
        if (!isAllowedTarget(targetStr))
            return crow::response(400, "Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");

        std::string ip = (isValidIP(targetStr)) ? targetStr : resolveDomainToIP(targetStr);
        if (ip.empty() || isPrivateIP(ip))
            return crow::response(400, "Access to private IP ranges is not allowed");

        std::string command = "whois " + targetStr;
        std::string output = exec(command.c_str());
        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // /nslookup endpoint.
    CROW_ROUTE(app, "/nslookup").methods("GET"_method)([](const crow::request& req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);
        if (!isAllowedTarget(targetStr))
            return crow::response(400, "Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");

        std::string ip = (isValidIP(targetStr)) ? targetStr : resolveDomainToIP(targetStr);
        if (ip.empty() || isPrivateIP(ip))
            return crow::response(400, "Access to private IP ranges is not allowed");

        std::string command = "nslookup " + targetStr;
        std::string output = exec(command.c_str());
        crow::json::wvalue result;
        result["result"] = output;
        return crow::response(result);
    });

    // /portscan endpoint: Supports scanning a single port or a range.
    CROW_ROUTE(app, "/portscan").methods("GET"_method)([&](const crow::request& req) {
        auto targetParam = req.url_params.get("target");
        if (!targetParam)
            return crow::response(400, "Missing target parameter");
        std::string targetStr(targetParam);

        // For port scanning, if target is a domain, resolve it.
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

        if (portStartParam && portEndParam) {
            int startPort, endPort;
            try {
                startPort = std::stoi(portStartParam);
                endPort = std::stoi(portEndParam);
            } catch (...) {
                return crow::response(400, "Invalid port range values");
            }
            if (startPort < 1 || endPort > 65535 || startPort > endPort)
                return crow::response(400, "Port range out of bounds or invalid");

            crow::json::wvalue scanRange;
            scanRange["start"] = startPort;
            scanRange["end"] = endPort;
            result["scan_range"] = std::move(scanRange);

            crow::json::wvalue scanResults;
            for (int p = startPort; p <= endPort; ++p) {
                bool open = check_port(targetStr, p, timeout_ms);
                scanResults[std::to_string(p)] = open;
            }
            result["results"] = std::move(scanResults);
            result["target"] = targetStr;
        }
        else if (portParam) {
            int port;
            try {
                port = std::stoi(portParam);
            } catch (...) {
                return crow::response(400, "Invalid port value");
            }
            if (port < 1 || port > 65535)
                return crow::response(400, "Port number out of range (1-65535)");
            bool open = check_port(targetStr, port, timeout_ms);
            result["target"] = targetStr;
            result["port"] = port;
            result["open"] = open;
        }
        else {
            return crow::response(400, "Missing port parameter. Specify either 'port' or both 'port_start' and 'port_end'");
        }
        return crow::response(result);
    });

    // Catch-all route for OPTIONS (preflight) requests.
    CROW_ROUTE(app, "/<path>")
    .methods("OPTIONS"_method)
    ([](const crow::request& req, const std::string& /*path*/) {
        crow::response res;
        res.code = 200;
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        return res;
    });

    app.port(18080).multithreaded().run();
    return 0;
}

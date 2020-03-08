/*
 * Copyright (C) 2020 Roman Ondráček <xondra58@stud.fit.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <arpa/inet.h>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <unistd.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <vector>

/**
 * Server socket
 */
int serverSocket;

/**
 * Resolves DNS A record
 * @param domainName Domain name
 * @return IPv4 address
 */
std::string resolveARecord(const std::string &domainName) {
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	int retVal = getaddrinfo(domainName.c_str(), nullptr, &hints, &result);
	if (retVal == EAI_NONAME) {
		throw std::domain_error("");
	}
	if (retVal != 0) {
		throw std::exception();
	}
	char address[INET6_ADDRSTRLEN];
	while (result != nullptr) {
		if (result->ai_family == AF_INET) {
			void *ptr = &((struct sockaddr_in *) result->ai_addr)->sin_addr;
			inet_ntop(result->ai_family, ptr, address, 100);
			freeaddrinfo(result);
			return std::string(address);
		}
		result = result->ai_next;
	}
	freeaddrinfo(result);
	throw std::domain_error("");
}

/**
 * Resolves DNS AAAA record
 * @param domainName Domain name
 * @return IPv4 address
 */
std::string resolveAaaaRecord(const std::string &domainName) {
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	int retVal = getaddrinfo(domainName.c_str(), nullptr, &hints, &result);
	if (retVal == EAI_NONAME) {
		throw std::domain_error("");
	}
	if (retVal != 0) {
		throw std::exception();
	}
	char address[INET6_ADDRSTRLEN];
	while (result != nullptr) {
		if (result->ai_family == AF_INET6) {
			void *ptr = &((struct sockaddr_in6 *) result->ai_addr)->sin6_addr;
			inet_ntop(result->ai_family, ptr, address, 100);
			freeaddrinfo(result);
			return std::string(address);
		}
		result = result->ai_next;
	}
	freeaddrinfo(result);
	throw std::domain_error("");
}

/**
 * Resolves DNS PTR record
 * @param address IP address
 * @return Domain name
 */
std::string resolvePtrRecord(const std::string &address) {
	struct sockaddr_in sa;
	char node[NI_MAXHOST];
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, address.c_str(), &sa.sin_addr);
	int retVal = getnameinfo((struct sockaddr *) &sa, sizeof(sa), node, sizeof(node), nullptr, 0, NI_IDN | NI_NAMEREQD);
	if (retVal == EAI_NONAME) {
		throw std::domain_error("");
	}
	if (retVal != 0) {
		throw std::exception();
	}
	return std::string(node);
}

/**
 * Creates HTTP/1.1 response
 * @param code HTTP Status Code
 * @param content Response content
 * @return HTTP/1.1 Response
 */
std::string createResponse(int code, const std::string &content = "") {
	std::string header;
	switch (code) {
		case 200:
			header = "HTTP/1.1 200 OK\n";
			break;
		case 400:
			header = "HTTP/1.1 400 Bad Request\n";
			break;
		case 404:
			header = "HTTP/1.1 404 Not Found\n";
			break;
		case 405:
			header = "HTTP/1.1 405 Method Not Allowed\n";
			break;
		default:
			header = "HTTP/1.1 500 Server Error";
	}
	char headerBuffer[100];
	snprintf(headerBuffer, sizeof(headerBuffer), "Content-Length: %lu\n", content.size());
	header.append(headerBuffer);
	header.append(
			"Content-Type: text/plain;charset=utf-8\nConnection: Closed\n\n");
	return header.append(content);
}

/**
 * Processes HTTP GET request
 * @param path Path
 * @return HTTP/1.1 response
 */
std::string processGet(const std::string &path) {
	std::string hdr("/resolve?name=");
	unsigned long pos0 = path.find(hdr);
	std::string param("&type=");
	unsigned long pos1 = path.find(param);
	if (pos0 != std::string::npos && pos1 != std::string::npos) {
		std::string name = path.substr(hdr.size(), pos1 - hdr.size());
		std::string type = path.substr(pos1 + param.size(), path.size() - pos1 - param.size());
		std::string result;
		try {
			if (type == "A") {
				result = resolveARecord(name);
			} else if (type == "AAAA") {
				result = resolveAaaaRecord(name);
			} else if (type == "PTR") {
				result = resolvePtrRecord(name);
			} else {
				return createResponse(400);
			}
			std::ostringstream oss;
			oss << name << ":" << type << "=" << result << std::endl;
			return createResponse(200, oss.str());
		} catch (const std::domain_error &e) {
			return createResponse(404);
		}
	}
	return createResponse(400);
}

/**
 * Processes HTTP POST request
 * @param path Path
 * @param iss String stream
 * @return HTTP/1.1 response
 */
std::string processPost(const std::string &path, std::istringstream &iss) {
	if (path != "/dns-query") {
		return createResponse(400);
	}
	bool emptyLine = false;
	std::string str;
	std::ostringstream oss;
	while (std::getline(iss, str, '\n')) {
		if (emptyLine) {
			int pos = str.find(':');
			std::string name = str.substr(0, pos);
			std::string type = str.substr(pos + 1);
			std::string result;
			try {
				if (type == "A") {
					result = resolveARecord(name);
				} else if (type == "AAAA") {
					result = resolveAaaaRecord(name);
				} else if (type == "PTR") {
					result = resolvePtrRecord(name);
				} else {
					return createResponse(400);
				}
				oss << name << ":" << type << "=" << result << std::endl;
			} catch (const std::domain_error &e) {
				return createResponse(404, "");
			}
		}
		if (str == "\r") {
			emptyLine = true;
		}
	}
	if (oss.str().empty()) {
		return createResponse(400, "");
	}
	return createResponse(200, oss.str());
}

/**
 * Starts HTTP/1.1 server
 * @param port Listening port
 */
void startServer(uint16_t port) {
	int clientSocket;
	struct sockaddr_in address = {};
	int opt = 1;
	socklen_t addressLen = sizeof(address);

	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(serverSocket, (struct sockaddr *) &address, sizeof(address)) < 0) {
		close(serverSocket);
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(serverSocket, 3) < 0) {
		close(serverSocket);
		perror("listen");
		exit(EXIT_FAILURE);
	}

	while (true) {
		char buffer[8192] = {0};

		clientSocket = accept(serverSocket, (struct sockaddr *) &address, &addressLen);
		if (clientSocket < 0) {
			shutdown(serverSocket, 0);
			close(serverSocket);
			perror("accept");
			exit(EXIT_FAILURE);
		}

		read(clientSocket, buffer, 8192);
		std::istringstream iss(buffer);
		std::string str, response;
		std::getline(iss, str, '\n');

		unsigned int pathPos = str.find(' ') + 1;
		unsigned long httpVerPos = str.find(" HTTP/1.1");
		if (httpVerPos == std::string::npos) {
			response = createResponse(400);
			send(clientSocket, response.c_str(), response.size(), 0);
			continue;
		}
		std::string method = str.substr(0, pathPos - 1);
		std::string path = str.substr(pathPos, httpVerPos - pathPos);

		if (method == "GET") {
			response = processGet(path);
		} else if (method == "POST") {
			response = processPost(path, iss);
		} else {
			response = createResponse(405);
		}

		send(clientSocket, response.c_str(), response.size(), 0);
	}
}

/**
 * Handles received signals
 * @param signal Signal number
 */
void signalHandler(int signal) {
	if (signal == SIGINT) {
		shutdown(serverSocket, 0);
		close(serverSocket);
	}
}


/**
 * Main function
 * @param argc Argument count
 * @param argv Arguments
 * @return Execution status
 */
int main(int argc, char *argv[]) {
	signal(SIGINT, signalHandler);
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
	} else {
		uint16_t port = std::stoul(argv[1]);
		startServer(port);
	}
	return EXIT_SUCCESS;
}
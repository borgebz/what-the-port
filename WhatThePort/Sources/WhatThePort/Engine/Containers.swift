import Darwin
import Foundation

/// A desktop app that publishes container ports on the Mac. Its helper process
/// holds every published port, so the port's real owner is the container,
/// and stopping that helper would take every container down with it.
enum ContainerRuntime: String, CaseIterable {
    case orbStack = "OrbStack"
    case docker = "Docker"

    /// Recognised by the listener's executable, since the kernel truncates long
    /// process names like `com.docker.backend`.
    static func owning(executablePath path: String) -> ContainerRuntime? {
        if path.contains("/OrbStack.app/") { return .orbStack }
        if path.contains("/Docker.app/") { return .docker }
        return nil
    }

    /// The Docker Engine API socket each app serves for its own containers.
    var socketPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        switch self {
        case .orbStack: return home + "/.orbstack/run/docker.sock"
        case .docker: return home + "/.docker/run/docker.sock"
        }
    }
}

/// A running container with at least one TCP port published on the Mac.
struct ContainerInfo: Equatable {
    let id: String
    let name: String
    let image: String
    let runtime: ContainerRuntime
    let publishedPorts: Set<Int>
    var composeProject: String?
    var composeService: String?
    /// The folder `docker compose` ran in, from the container's labels.
    var workingDirectory: String?

    var shortID: String { String(id.prefix(12)) }

    /// `postgres:16-alpine` → `postgres`, `ghcr.io/saleor/saleor:3.22` → `saleor`.
    var imageName: String {
        let path = image.split(separator: "@").first.map(String.init) ?? image
        let last = path.split(separator: "/").last.map(String.init) ?? path
        return last.split(separator: ":").first.map(String.init) ?? last
    }

    /// Matches the protected process list against what the image runs, so
    /// `postgres`, `redis` (`redis-server`) and `mongo` (`mongod`) containers
    /// are protected like the native servers.
    func isProtected(by names: Set<String>) -> Bool {
        let base = imageName.lowercased()
        return [base, base + "-server", base + "d"].contains(where: names.contains)
    }
}

/// Cumulative usage, in the same units the process inspector reports.
struct ContainerUsage: Equatable {
    let memory: UInt64
    let cpuNanoseconds: UInt64
}

/// A minimal Docker Engine API client over the runtime's unix socket. Menu bar
/// apps don't get the shell's PATH, so this avoids depending on the CLI.
enum DockerEngine {
    static func containers(_ runtime: ContainerRuntime) -> [ContainerInfo]? {
        guard let body = request("GET", "/containers/json", runtime: runtime),
              let list = try? JSONSerialization.jsonObject(with: body) as? [[String: Any]] else { return nil }
        return list.compactMap { parseContainer($0, runtime: runtime) }
    }

    static func usage(_ id: String, runtime: ContainerRuntime) -> ContainerUsage? {
        guard let body = request("GET", "/containers/\(id)/stats?stream=false&one-shot=true", runtime: runtime),
              let stats = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
        return parseUsage(stats)
    }

    static func startedAt(_ id: String, runtime: ContainerRuntime) -> Date? {
        guard let body = request("GET", "/containers/\(id)/json", runtime: runtime),
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let state = json["State"] as? [String: Any],
              let started = state["StartedAt"] as? String else { return nil }
        return parseDate(started)
    }

    /// `docker stop`: SIGTERM, then SIGKILL after the container's own timeout.
    static func stop(_ container: ContainerInfo, completion: ((Bool) -> Void)? = nil) {
        post("/containers/\(container.id)/stop", runtime: container.runtime, completion: completion)
    }

    static func restart(_ container: ContainerInfo, completion: ((Bool) -> Void)? = nil) {
        post("/containers/\(container.id)/restart", runtime: container.runtime, completion: completion)
    }

    private static func post(_ path: String, runtime: ContainerRuntime, completion: ((Bool) -> Void)?) {
        DispatchQueue.global().async {
            // Stop waits for the container to exit, up to its stop timeout.
            let ok = request("POST", path, runtime: runtime, timeout: 60) != nil
            if let completion { DispatchQueue.main.async { completion(ok) } }
        }
    }

    // MARK: - Parsing

    static func parseContainer(_ json: [String: Any], runtime: ContainerRuntime) -> ContainerInfo? {
        guard let id = json["Id"] as? String else { return nil }
        let ports = (json["Ports"] as? [[String: Any]] ?? []).compactMap { port -> Int? in
            guard (port["Type"] as? String) == "tcp" else { return nil }
            return port["PublicPort"] as? Int
        }
        guard !ports.isEmpty else { return nil }
        let names = json["Names"] as? [String] ?? []
        let name = names.first.map { $0.hasPrefix("/") ? String($0.dropFirst()) : $0 } ?? String(id.prefix(12))
        let labels = json["Labels"] as? [String: String] ?? [:]
        return ContainerInfo(id: id, name: name, image: json["Image"] as? String ?? "", runtime: runtime,
                             publishedPorts: Set(ports),
                             composeProject: labels["com.docker.compose.project"],
                             composeService: labels["com.docker.compose.service"],
                             workingDirectory: labels["com.docker.compose.project.working_dir"])
    }

    /// Memory as `docker stats` counts it: usage minus reclaimable page cache.
    static func parseUsage(_ stats: [String: Any]) -> ContainerUsage? {
        guard let memory = stats["memory_stats"] as? [String: Any],
              let used = (memory["usage"] as? NSNumber)?.uint64Value,
              let cpu = stats["cpu_stats"] as? [String: Any],
              let total = ((cpu["cpu_usage"] as? [String: Any])?["total_usage"] as? NSNumber)?.uint64Value else { return nil }
        let details = memory["stats"] as? [String: Any] ?? [:]
        let cache = ((details["inactive_file"] ?? details["total_inactive_file"]) as? NSNumber)?.uint64Value ?? 0
        return ContainerUsage(memory: used > cache ? used - cache : used, cpuNanoseconds: total)
    }

    private static func parseDate(_ string: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: string) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: string)
    }

    // MARK: - HTTP over a unix socket

    /// Returns the response body for a 2xx status, otherwise nil.
    static func request(_ method: String, _ path: String, runtime: ContainerRuntime, timeout: Int = 2) -> Data? {
        let socketPath = runtime.socketPath
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var time = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &time, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &time, socklen_t(MemoryLayout<timeval>.size))
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { return nil }

        let message = "\(method) \(path) HTTP/1.0\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        let sent = message.utf8CString.withUnsafeBufferPointer { send(fd, $0.baseAddress, $0.count - 1, 0) }
        guard sent == message.utf8.count else { return nil }

        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = recv(fd, &buffer, buffer.count, 0)
            if count <= 0 { break }
            response.append(buffer, count: count)
        }
        return parseResponse(response)
    }

    static func parseResponse(_ response: Data) -> Data? {
        guard let split = response.range(of: Data("\r\n\r\n".utf8)),
              let head = String(data: response[..<split.lowerBound], encoding: .utf8) else { return nil }
        let lines = head.components(separatedBy: "\r\n")
        let status = lines.first?.split(separator: " ").dropFirst().first.flatMap { Int($0) } ?? 0
        guard (200..<300).contains(status) else { return nil }
        let body = response[split.upperBound...]
        let chunked = lines.contains { $0.lowercased().hasPrefix("transfer-encoding:") && $0.lowercased().contains("chunked") }
        return chunked ? dechunk(Data(body)) : Data(body)
    }

    private static func dechunk(_ data: Data) -> Data {
        var result = Data()
        var index = data.startIndex
        let crlf = Data("\r\n".utf8)
        while let line = data.range(of: crlf, in: index..<data.endIndex),
              let sizeText = String(data: data[index..<line.lowerBound], encoding: .ascii),
              let size = Int(sizeText.split(separator: ";").first ?? "", radix: 16), size > 0 {
            let start = line.upperBound
            let end = data.index(start, offsetBy: size, limitedBy: data.endIndex) ?? data.endIndex
            result.append(data[start..<end])
            index = data.index(end, offsetBy: 2, limitedBy: data.endIndex) ?? data.endIndex
        }
        return result
    }
}
